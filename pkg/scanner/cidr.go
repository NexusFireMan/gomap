package scanner

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// DiscoveryOptions controls CIDR host discovery behavior.
type DiscoveryOptions struct {
	Ports      []int
	Timeout    time.Duration
	NumWorkers int
}

// ExpandCIDR expands a CIDR notation to a list of IPs
func ExpandCIDR(cidr string) ([]string, error) {
	// Check if it's a single IP address
	if !strings.Contains(cidr, "/") {
		// If literal IP is provided, keep it as-is (avoid DNS lookup side-effects).
		if ip := net.ParseIP(cidr); ip != nil {
			return []string{ip.String()}, nil
		}

		// Try to resolve as hostname/IP
		ips, err := net.LookupIP(cidr)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("invalid IP address or hostname: %s", cidr)
		}
		// Prefer IPv4 for consistency with many local lab/network setups.
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				return []string{v4.String()}, nil
			}
		}
		// Fall back to first resolved address (likely IPv6-only host).
		return []string{ips[0].String()}, nil
	}

	// Parse CIDR notation
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR notation: %s - %v", cidr, err)
	}

	// If it's a /32 (single host), just return it
	if ipnet.IP.String() == ip.String() {
		ones, bits := ipnet.Mask.Size()
		if ones == bits {
			return []string{ip.String()}, nil
		}
	}

	// Calculate number of hosts
	ones, bits := ipnet.Mask.Size()
	hostBits := bits - ones
	numHosts := 1 << uint(hostBits)

	// For large CIDR blocks, limit the expansion
	maxHosts := 65536 // 65K hosts max (256^2)
	if numHosts > maxHosts {
		return nil, fmt.Errorf("CIDR range too large (%d hosts). Maximum: %d hosts. Use a smaller range", numHosts, maxHosts)
	}

	var ips []string
	ip = ipnet.IP.Mask(ipnet.Mask)

	for i := 0; i < numHosts; i++ {
		// Skip network address and broadcast address for non-/31 and non-/32 networks
		if hostBits > 1 && (i == 0 || i == numHosts-1) {
			incrementIP(ip)
			continue
		}

		ips = append(ips, ip.String())
		incrementIP(ip)
	}

	return ips, nil
}

// incrementIP increments an IP address by 1
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ParseTargets parses target(s) which can be single IP, multiple IPs, or CIDR notation
// Format: "192.168.1.1" or "192.168.1.0/24" or "192.168.1.1,192.168.1.5"
func ParseTargets(target string) ([]string, error) {
	targets := strings.Split(target, ",")
	var allIPs []string

	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}

		ips, err := ExpandCIDR(t)
		if err != nil {
			return nil, err
		}

		allIPs = append(allIPs, ips...)
	}

	if len(allIPs) == 0 {
		return nil, fmt.Errorf("no valid targets found")
	}

	return allIPs, nil
}

// FormatCIDRInfo returns a human-readable description of what will be scanned
func FormatCIDRInfo(target string) (string, int, error) {
	ips, err := ParseTargets(target)
	if err != nil {
		return "", 0, err
	}

	if len(ips) == 1 {
		return ips[0], 1, nil
	}

	// For CIDR, return first-last notation
	return fmt.Sprintf("%s-%s", ips[0], ips[len(ips)-1]), len(ips), nil
}

// IsCIDR checks if a target is a CIDR range or single IP
func IsCIDR(target string) bool {
	// Remove commas if multiple targets
	targets := strings.Split(target, ",")
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if strings.Contains(t, "/") {
			return true
		}
	}
	return false
}

// DiscoverActiveHosts performs a quick host discovery on a CIDR range
// It attempts to connect to common ports (443, 80, 22, 445, 3306) to determine if hosts are active
func DiscoverActiveHosts(hosts []string, timeout time.Duration, numWorkers int) []string {
	return DiscoverActiveHostsWithOptions(hosts, DiscoveryOptions{
		Ports:      []int{443, 80, 22, 445, 3306, 8080, 3389},
		Timeout:    timeout,
		NumWorkers: numWorkers,
	})
}

// DiscoverActiveHostsWithOptions performs host discovery using configurable probe ports and concurrency.
func DiscoverActiveHostsWithOptions(hosts []string, opts DiscoveryOptions) []string {
	if len(hosts) <= 1 {
		// Skip discovery for single IPs or empty lists
		return hosts
	}

	commonPorts := opts.Ports
	if len(commonPorts) == 0 {
		commonPorts = []int{443, 80, 22}
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	numWorkers := opts.NumWorkers
	if numWorkers <= 0 {
		numWorkers = 25
	}
	activeChan := make(chan string, len(hosts))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, numWorkers)

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire slot
			defer func() { <-semaphore }() // Release slot

			if isHostActive(h, commonPorts, timeout) {
				activeChan <- h
			}
		}(host)
	}

	go func() {
		wg.Wait()
		close(activeChan)
	}()

	var activeHosts []string
	for host := range activeChan {
		activeHosts = append(activeHosts, host)
	}

	return activeHosts
}

// isHostActive checks if a host is reachable by attempting connections to common ports
func isHostActive(host string, ports []int, timeout time.Duration) bool {
	for _, port := range ports {
		address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err == nil {
			_ = conn.Close()
			return true
		}
	}
	return false
}
