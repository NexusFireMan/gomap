package scanner

import (
	"crypto/tls"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"time"
)

// InterfaceSourceIPs returns usable addresses already assigned to an interface.
func InterfaceSourceIPs(name string) ([]net.IP, error) {
	iface, err := net.InterfaceByName(strings.TrimSpace(name))
	if err != nil {
		return nil, fmt.Errorf("source interface %q not found: %w", name, err)
	}
	if iface.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("source interface %q is down", name)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("cannot read addresses from source interface %q: %w", name, err)
	}

	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		ip, _, parseErr := net.ParseCIDR(addr.String())
		if parseErr != nil || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		ips = append(ips, append(net.IP(nil), ip...))
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("source interface %q has no usable IP addresses", name)
	}
	return ips, nil
}

// ValidateSourceIPsForTargets prevents an implicit fallback to the default
// source address when an interface has no address for a target's IP family.
func ValidateSourceIPsForTargets(ips []net.IP, targets []string) error {
	for _, target := range targets {
		targetIP := net.ParseIP(target)
		if targetIP == nil {
			continue
		}
		matched := false
		for _, sourceIP := range ips {
			if (targetIP.To4() != nil) == (sourceIP.To4() != nil) {
				matched = true
				break
			}
		}
		if !matched {
			family := "IPv6"
			if targetIP.To4() != nil {
				family = "IPv4"
			}
			return fmt.Errorf("source interface has no assigned %s address for target %s", family, target)
		}
	}
	return nil
}

func (s *Scanner) dialTCP(address string, timeout time.Duration) (net.Conn, error) {
	dialer := s.dialerFor("tcp", address, timeout)
	return dialer.Dial("tcp", address)
}

func (s *Scanner) dialUDP(address string, timeout time.Duration) (net.Conn, error) {
	dialer := s.dialerFor("udp", address, timeout)
	return dialer.Dial("udp", address)
}

func (s *Scanner) dialTLS(address string, timeout time.Duration, cfg *tls.Config) (*tls.Conn, error) {
	dialer := s.dialerFor("tcp", address, timeout)
	return tls.DialWithDialer(dialer, "tcp", address, cfg)
}

func (s *Scanner) dialerFor(network, address string, timeout time.Duration) *net.Dialer {
	return dialerForSourceIPs(s.SourceIPs, network, address, timeout)
}

func dialerForSourceIPs(ips []net.IP, network, address string, timeout time.Duration) *net.Dialer {
	dialer := &net.Dialer{Timeout: timeout}
	ip := randomCompatibleSourceIP(ips, address)
	if ip == nil {
		return dialer
	}
	if strings.HasPrefix(network, "udp") {
		dialer.LocalAddr = &net.UDPAddr{IP: ip}
	} else {
		dialer.LocalAddr = &net.TCPAddr{IP: ip}
	}
	return dialer
}

func randomCompatibleSourceIP(ips []net.IP, address string) net.IP {
	if len(ips) == 0 {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil
	}
	target := net.ParseIP(strings.Trim(host, "[]"))
	if target == nil {
		return append(net.IP(nil), ips[rand.IntN(len(ips))]...)
	}

	compatible := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if (target.To4() != nil) == (ip.To4() != nil) {
			compatible = append(compatible, ip)
		}
	}
	if len(compatible) == 0 {
		return nil
	}
	return append(net.IP(nil), compatible[rand.IntN(len(compatible))]...)
}
