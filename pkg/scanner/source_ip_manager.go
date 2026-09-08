package scanner

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
)

const maxManagedSourceIPs = 64

type interfaceAddressBackend interface {
	List(string) ([]*net.IPNet, error)
	Add(string, *net.IPNet) error
	Delete(string, *net.IPNet) error
}

// ManagedSourceIPs tracks only addresses added by this process.
type ManagedSourceIPs struct {
	interfaceName string
	backend       interfaceAddressBackend
	ips           []net.IP
	added         []*net.IPNet
	closeOnce     sync.Once
	closeErr      error
	setupMu       sync.Mutex
	signalMu      sync.Mutex
	signalStop    func()
}

// PrepareManagedSourceIPs adds explicit addresses and rolls back partial setup failures.
func PrepareManagedSourceIPs(interfaceName, spec string) (*ManagedSourceIPs, error) {
	if err := requireSourceIPPrivileges(); err != nil {
		return nil, err
	}
	backend, err := newSystemAddressBackend()
	if err != nil {
		return nil, err
	}
	return prepareManagedSourceIPs(interfaceName, spec, backend, (*ManagedSourceIPs).InstallSignalCleanup)
}

func prepareManagedSourceIPsWithBackend(interfaceName, spec string, backend interfaceAddressBackend) (*ManagedSourceIPs, error) {
	return prepareManagedSourceIPs(interfaceName, spec, backend, nil)
}

func prepareManagedSourceIPs(interfaceName, spec string, backend interfaceAddressBackend, onPrepare func(*ManagedSourceIPs)) (*ManagedSourceIPs, error) {
	interfaceName = strings.TrimSpace(interfaceName)
	if interfaceName == "" {
		return nil, errors.New("source interface cannot be empty")
	}
	requested, err := parseManagedSourceIPs(spec)
	if err != nil {
		return nil, err
	}
	existing, err := backend.List(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("cannot inspect source interface %q: %w", interfaceName, err)
	}

	managed := &ManagedSourceIPs{
		interfaceName: interfaceName,
		backend:       backend,
		ips:           make([]net.IP, 0, len(requested)),
		added:         make([]*net.IPNet, 0, len(requested)),
	}
	// Cleanup must wait until every successful add is recorded, including an
	// in-flight netlink operation when a termination signal arrives.
	managed.setupMu.Lock()
	if onPrepare != nil {
		onPrepare(managed)
	}
	for _, addr := range requested {
		managed.ips = append(managed.ips, append(net.IP(nil), addr.IP...))
		if containsIP(existing, addr.IP) {
			continue
		}
		if err := backend.Add(interfaceName, addr); err != nil {
			managed.setupMu.Unlock()
			rollbackErr := managed.Close()
			return nil, errors.Join(fmt.Errorf("cannot add source IP %s to %s: %w", addr, interfaceName, err), rollbackErr)
		}
		managed.added = append(managed.added, cloneIPNet(addr))
		existing = append(existing, cloneIPNet(addr))
	}
	managed.setupMu.Unlock()
	return managed, nil
}

func parseManagedSourceIPs(spec string) ([]*net.IPNet, error) {
	parts := strings.Split(spec, ",")
	if len(parts) > maxManagedSourceIPs {
		return nil, fmt.Errorf("too many source IPs: maximum is %d", maxManagedSourceIPs)
	}
	result := make([]*net.IPNet, 0, len(parts))
	seen := make(map[netip.Addr]struct{}, len(parts))
	for _, raw := range parts {
		value := strings.TrimSpace(raw)
		if value == "" {
			return nil, errors.New("source IP list contains an empty entry")
		}

		var prefix netip.Prefix
		var err error
		if strings.Contains(value, "/") {
			prefix, err = netip.ParsePrefix(value)
		} else {
			addr, parseErr := netip.ParseAddr(value)
			if parseErr != nil {
				err = parseErr
			} else {
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			}
		}
		if err != nil || !prefix.IsValid() {
			return nil, fmt.Errorf("invalid source IP %q", value)
		}
		if prefix.Addr().Is4In6() {
			return nil, fmt.Errorf("IPv4-mapped IPv6 source IP %q is unsupported; use IPv4 notation", value)
		}
		addr := prefix.Addr()
		if addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
			return nil, fmt.Errorf("source IP %q is not usable for managed rotation", value)
		}
		if isIPv4NetworkOrBroadcast(addr, prefix.Bits()) {
			return nil, fmt.Errorf("source IP %q is a network or broadcast address", value)
		}
		if _, exists := seen[addr]; exists {
			return nil, fmt.Errorf("duplicate source IP %s", addr)
		}
		seen[addr] = struct{}{}

		bits := prefix.Bits()
		ip := net.IP(addr.AsSlice())
		result = append(result, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, addr.BitLen())})
	}
	if len(result) == 0 {
		return nil, errors.New("at least one source IP is required")
	}
	return result, nil
}

func isIPv4NetworkOrBroadcast(addr netip.Addr, prefixBits int) bool {
	if !addr.Is4() || prefixBits >= 31 {
		return false
	}
	value := binary.BigEndian.Uint32(addr.AsSlice())
	mask := ^uint32(0) << (32 - prefixBits)
	network := value & mask
	broadcast := network | ^mask
	return value == network || value == broadcast
}

// IPs returns a defensive copy of the requested rotation pool.
func (m *ManagedSourceIPs) IPs() []net.IP {
	result := make([]net.IP, 0, len(m.ips))
	for _, ip := range m.ips {
		result = append(result, append(net.IP(nil), ip...))
	}
	return result
}

// AddedCount reports how many requested addresses were not already configured.
func (m *ManagedSourceIPs) AddedCount() int {
	return len(m.added)
}

// Close removes only addresses successfully added by this manager.
func (m *ManagedSourceIPs) Close() error {
	m.closeOnce.Do(func() {
		m.setupMu.Lock()
		defer m.setupMu.Unlock()
		var cleanupErrs []error
		for i := len(m.added) - 1; i >= 0; i-- {
			if err := m.backend.Delete(m.interfaceName, m.added[i]); err != nil {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("cannot remove source IP %s from %s: %w", m.added[i], m.interfaceName, err))
			}
		}
		m.closeErr = errors.Join(cleanupErrs...)
		m.stopSignalCleanup()
	})
	return m.closeErr
}

// InstallSignalCleanup removes managed addresses before terminating on common signals.
func (m *ManagedSourceIPs) InstallSignalCleanup() {
	m.signalMu.Lock()
	defer m.signalMu.Unlock()
	if m.signalStop == nil {
		m.signalStop = installManagedSignalCleanup(m)
	}
}

func (m *ManagedSourceIPs) stopSignalCleanup() {
	m.signalMu.Lock()
	defer m.signalMu.Unlock()
	if m.signalStop != nil {
		m.signalStop()
		m.signalStop = nil
	}
}

func containsIP(addrs []*net.IPNet, ip net.IP) bool {
	for _, addr := range addrs {
		if addr != nil && addr.IP.Equal(ip) {
			return true
		}
	}
	return false
}

func cloneIPNet(addr *net.IPNet) *net.IPNet {
	if addr == nil {
		return nil
	}
	return &net.IPNet{
		IP:   append(net.IP(nil), addr.IP...),
		Mask: append(net.IPMask(nil), addr.Mask...),
	}
}
