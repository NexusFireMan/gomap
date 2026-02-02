package main

import (
	"fmt"
	"strconv"
	"strings"
)

// PortManager handles port parsing and service mapping
type PortManager struct {
	serviceMap map[int]string
}

// NewPortManager creates a new PortManager instance
func NewPortManager() *PortManager {
	return &PortManager{
		serviceMap: initServiceMap(),
	}
}

// GetPortsToScan returns the list of ports to scan based on the specification
func (pm *PortManager) GetPortsToScan(portsStr string) ([]int, error) {
	if portsStr == "-" {
		return getAllPorts(), nil
	}
	if portsStr != "" {
		return pm.ParsePorts(portsStr)
	}
	return getTop1000Ports(), nil
}

// ParsePorts parses a port specification string
func (pm *PortManager) ParsePorts(portsStr string) ([]int, error) {
	if strings.Contains(portsStr, "-") {
		return pm.parsePortRange(portsStr)
	}

	if strings.Contains(portsStr, ",") {
		return pm.parsePortList(portsStr)
	}

	return pm.parseSinglePort(portsStr)
}

// parsePortRange parses a port range (e.g., "1-1024")
func (pm *PortManager) parsePortRange(portsStr string) ([]int, error) {
	parts := strings.Split(portsStr, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid port range")
	}

	start, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, err
	}

	end, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, err
	}

	if start < 1 || end > 65535 || start > end {
		return nil, fmt.Errorf("invalid port range")
	}

	ports := make([]int, 0, end-start+1)
	for i := start; i <= end; i++ {
		ports = append(ports, i)
	}
	return ports, nil
}

// parsePortList parses a comma-separated list of ports (e.g., "80,443,8080")
func (pm *PortManager) parsePortList(portsStr string) ([]int, error) {
	ports := make([]int, 0)
	parts := strings.Split(portsStr, ",")

	for _, part := range parts {
		port, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port number: %d", port)
		}
		ports = append(ports, port)
	}
	return ports, nil
}

// parseSinglePort parses a single port number
func (pm *PortManager) parseSinglePort(portsStr string) ([]int, error) {
	port, err := strconv.Atoi(portsStr)
	if err != nil {
		return nil, err
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid port number: %d", port)
	}
	return []int{port}, nil
}

// GetServiceName returns the service name for a given port
func (pm *PortManager) GetServiceName(port int, bannerService string) string {
	if bannerService != "" {
		return bannerService
	}
	if service, ok := pm.serviceMap[port]; ok {
		return service
	}
	return ""
}

// getAllPorts returns all ports from 1 to 65535
func getAllPorts() []int {
	ports := make([]int, 65535)
	for i := 1; i <= 65535; i++ {
		ports[i-1] = i
	}
	return ports
}

// initServiceMap initializes the service mapping for common ports
func initServiceMap() map[int]string {
	return map[int]string{
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "domain",
		80:    "http",
		110:   "pop3",
		111:   "rpcbind",
		135:   "msrpc",
		139:   "netbios-ssn",
		143:   "imap",
		389:   "ldap",
		443:   "https",
		445:   "microsoft-ds",
		465:   "smtps",
		631:   "ipp",
		636:   "ldaps",
		993:   "imaps",
		995:   "pop3s",
		1433:  "mssql",
		1521:  "oracle",
		1723:  "pptp",
		3306:  "mysql",
		3389:  "ms-wbt-server",
		4848:  "http",
		5432:  "postgresql",
		5900:  "vnc",
		5901:  "vnc",
		5902:  "vnc",
		5903:  "vnc",
		5985:  "http",
		5986:  "http",
		6379:  "redis",
		7676:  "jms",
		8080:  "http",
		8181:  "intermapper",
		8383:  "http-alt",
		8443:  "https-alt",
		9200:  "elasticsearch",
		9300:  "elasticsearch",
		11211: "memcached",
		27017: "mongodb",
		27018: "mongodb",
		27019: "mongodb",
		27020: "mongodb",
		50070: "hadoop",
		49152: "msrpc",
		49153: "msrpc",
		49154: "msrpc",
		49155: "msrpc",
	}
}
