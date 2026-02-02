package main

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// ParseBanner extracts service name and version from a banner
func parseBanner(banner string) (service, version string) {
	// First check if it's HTTP - we need full banner for this
	if strings.Contains(banner, "HTTP/") {
		if s, v := parseHTTP(banner); s != "" {
			return s, v
		}
	}

	// For other services, sanitize banner (keep only first line)
	banner = sanitizeBanner(banner)

	if banner == "" {
		return "", ""
	}

	// Check service-specific parsers in order
	if service, version := parseSSH(banner); service != "" {
		return service, version
	}

	if service, version := parseOpenSSHDetailed(banner); service != "" {
		return service, version
	}

	if service, version := parseFTP(banner); service != "" {
		return service, version
	}

	if service, version := parseMySQL(banner); service != "" {
		return service, version
	}

	if service, version := parsePostgreSQL(banner); service != "" {
		return service, version
	}

	if service, version := parseRedis(banner); service != "" {
		return service, version
	}

	if service, version := parseMicrosoftServices(banner); service != "" {
		return service, version
	}

	if service, version := parseElasticsearch(banner); service != "" {
		return service, version
	}

	if service, version := parseJMS(banner); service != "" {
		return service, version
	}

	if service, version := parseGlassFish(banner); service != "" {
		return service, version
	}

	if service, version := parseSMB(banner); service != "" {
		return service, version
	}

	return "", ""
}

// sanitizeBanner removes non-printable characters and normalizes whitespace
func sanitizeBanner(banner string) string {
	// Remove null bytes and control characters, keep only printable chars
	var sanitized strings.Builder
	for _, r := range banner {
		if unicode.IsPrint(r) || r == '\n' || r == '\r' || r == '\t' {
			sanitized.WriteRune(r)
		}
	}

	result := sanitized.String()
	result = strings.TrimSpace(result)

	// Take only first line for initial processing
	lines := strings.Split(result, "\n")
	if len(lines) > 0 {
		result = lines[0]
	}
	result = strings.TrimSpace(result)

	return result
}

// parseSSH extracts SSH version information
func parseSSH(banner string) (string, string) {
	if !strings.Contains(banner, "SSH") {
		return "", ""
	}

	// SSH Protocol detection: SSH-2.0-OpenSSH_7.4p1 or SSH-1.99-OpenSSH_3.9p1
	sshRegex := regexp.MustCompile(`^SSH-([\d\.]+)-(.+)$`)
	if match := sshRegex.FindStringSubmatch(banner); match != nil {
		protocol := match[1]
		implementation := match[2]
		implementation = strings.TrimSpace(implementation)
		implementation = strings.Replace(implementation, "_", " ", -1)

		// Add protocol version info
		var protocolInfo string
		switch protocol {
		case "2.0":
			protocolInfo = "SSH-2.0"
		case "1.99":
			protocolInfo = "SSH-1.99"
		case "1.0":
			protocolInfo = "SSH-1.0"
		default:
			protocolInfo = "SSH-" + protocol
		}

		// Try to extract specific implementation
		if strings.Contains(implementation, "OpenSSH") {
			// Extract version details
			opensshRegex := regexp.MustCompile(`OpenSSH[\s_]+([\d\.]+)(?:p(\d+))?`)
			if match := opensshRegex.FindStringSubmatch(implementation); match != nil {
				version := match[1]
				patch := match[2]
				if patch != "" {
					return "ssh", fmt.Sprintf("%s - OpenSSH %sp%s", protocolInfo, version, patch)
				}
				return "ssh", fmt.Sprintf("%s - OpenSSH %s", protocolInfo, version)
			}
		} else if strings.Contains(implementation, "libssh") {
			return "ssh", fmt.Sprintf("%s - libssh", protocolInfo)
		} else if strings.Contains(implementation, "PuTTY") {
			return "ssh", fmt.Sprintf("%s - PuTTY", protocolInfo)
		}

		return "ssh", fmt.Sprintf("%s - %s", protocolInfo, implementation)
	}
	return "", ""
}

// parseFTP extracts FTP server information
func parseFTP(banner string) (string, string) {
	if !strings.HasPrefix(banner, "220") {
		return "", ""
	}

	// Extract version info from FTP banner
	// Format: "220 <server> <version> ..."
	ftpRegex := regexp.MustCompile(`^220[\s-]+([^()]+)(?:\s*\(([^)]+)\))?`)
	if match := ftpRegex.FindStringSubmatch(banner); match != nil {
		serverInfo := strings.TrimSpace(match[1])
		version := strings.TrimSpace(match[2])

		// Detect and normalize server names with versions
		if strings.Contains(serverInfo, "Microsoft") {
			if version != "" {
				return "ftp", fmt.Sprintf("Microsoft FTP %s", version)
			}
			return "ftp", "Microsoft FTP"
		}

		if strings.Contains(serverInfo, "ProFTPD") {
			// Extract ProFTPD version: "ProFTPD 1.3.5c"
			proftpdRegex := regexp.MustCompile(`ProFTPD[\s]+([\d\.]+[a-z]?)`)
			if match := proftpdRegex.FindStringSubmatch(banner); match != nil {
				return "ftp", fmt.Sprintf("ProFTPD %s", match[1])
			}
			return "ftp", "ProFTPD"
		}

		if strings.Contains(serverInfo, "vsFTPd") || strings.Contains(serverInfo, "vsftpd") {
			vsFtpdRegex := regexp.MustCompile(`vsftpd[\s]+([\d\.]+[a-z]?)`)
			if match := vsFtpdRegex.FindStringSubmatch(banner); match != nil {
				return "ftp", fmt.Sprintf("vsFTPd %s", match[1])
			}
			return "ftp", "vsFTPd"
		}

		if strings.Contains(serverInfo, "Pure-FTPd") || strings.Contains(serverInfo, "Pure FTPd") {
			pureFtpdRegex := regexp.MustCompile(`Pure[\s-]?FTPd[\s]+([\d\.]+[a-z]?)`)
			if match := pureFtpdRegex.FindStringSubmatch(banner); match != nil {
				return "ftp", fmt.Sprintf("Pure-FTPd %s", match[1])
			}
			return "ftp", "Pure-FTPd"
		}

		if strings.Contains(serverInfo, "FileZilla") {
			filezillaRegex := regexp.MustCompile(`FileZilla[\s]+([\d\.]+[a-z]?)`)
			if match := filezillaRegex.FindStringSubmatch(banner); match != nil {
				return "ftp", fmt.Sprintf("FileZilla %s", match[1])
			}
			return "ftp", "FileZilla"
		}

		if strings.Contains(serverInfo, "Gene6") || strings.Contains(serverInfo, "Gene 6") {
			return "ftp", "Gene6 FTP Server"
		}

		return "ftp", serverInfo
	}
	return "", ""
}

// parseHTTP extracts HTTP server information with version
func parseHTTP(banner string) (string, string) {
	// Check if it starts with HTTP response
	if !strings.Contains(banner, "HTTP/") {
		return "", ""
	}

	lines := strings.Split(banner, "\n")
	var statusLine, serverHeader string

	// First pass: Get status line and Server header
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lowerLine := strings.ToLower(line)

		// Extract HTTP status line
		if strings.HasPrefix(line, "HTTP/") && statusLine == "" {
			statusLine = line
		}

		// Match "Server:" header
		if strings.HasPrefix(lowerLine, "server:") {
			serverHeader = strings.TrimPrefix(line, "Server:")
			if serverHeader == "" {
				serverHeader = strings.TrimPrefix(line, "server:")
			}
			serverHeader = strings.TrimSpace(serverHeader)
			serverHeader = strings.Replace(serverHeader, "\r", "", -1)
			break
		}
	}

	// If we found a server header, parse it for detailed version info
	if serverHeader != "" {
		// Clean up common variations
		serverHeader = strings.TrimSpace(serverHeader)

		// Detect specific servers with version parsing
		if v := parseApacheVersion(serverHeader); v != "" {
			return "http", v
		}
		if v := parseNginxVersion(serverHeader); v != "" {
			return "http", v
		}
		if v := parseIISVersion(serverHeader); v != "" {
			return "http", v
		}
		if v := parseTomcatVersion(serverHeader); v != "" {
			return "http", v
		}
		if v := parseNodeVersion(serverHeader); v != "" {
			return "http", v
		}

		return "http", serverHeader
	}

	// If no Server header found but HTTP response exists, it's still HTTP
	if statusLine != "" {
		return "http", ""
	}

	return "", ""
}

// parseApacheVersion extracts Apache version from Server header
func parseApacheVersion(serverHeader string) string {
	if !strings.Contains(serverHeader, "Apache") {
		return ""
	}

	// Match patterns like "Apache/2.4.41", "Apache 2.4.41", etc.
	apacheRegex := regexp.MustCompile(`Apache[/-]?([\d\.]+(?:[.-][\w]+)?)`)
	if match := apacheRegex.FindStringSubmatch(serverHeader); match != nil {
		version := match[1]
		// Extract additional details (Ubuntu, Debian, etc.)
		if strings.Contains(serverHeader, "Ubuntu") {
			return fmt.Sprintf("Apache %s (Ubuntu)", version)
		}
		if strings.Contains(serverHeader, "Debian") {
			return fmt.Sprintf("Apache %s (Debian)", version)
		}
		if strings.Contains(serverHeader, "CentOS") {
			return fmt.Sprintf("Apache %s (CentOS)", version)
		}
		return fmt.Sprintf("Apache %s", version)
	}
	return ""
}

// parseNginxVersion extracts Nginx version from Server header
func parseNginxVersion(serverHeader string) string {
	if !strings.Contains(serverHeader, "nginx") {
		return ""
	}

	nginxRegex := regexp.MustCompile(`nginx[/-]?([\d\.]+(?:[.-][\w]+)?)`)
	if match := nginxRegex.FindStringSubmatch(serverHeader); match != nil {
		return fmt.Sprintf("Nginx %s", match[1])
	}
	return ""
}

// parseIISVersion extracts IIS version from Server header
func parseIISVersion(serverHeader string) string {
	if !strings.Contains(serverHeader, "IIS") && !strings.Contains(serverHeader, "Microsoft-IIS") {
		return ""
	}

	iisRegex := regexp.MustCompile(`Microsoft-IIS[/-]?([\d\.]+)`)
	if match := iisRegex.FindStringSubmatch(serverHeader); match != nil {
		version := match[1]
		// Map IIS versions
		iisVersionMap := map[string]string{
			"10.0": "Windows Server 2016 or later",
			"8.5":  "Windows Server 2012 R2",
			"8.0":  "Windows Server 2012",
			"7.5":  "Windows Server 2008 R2 or Windows 7",
			"7.0":  "Windows Server 2008 or Windows Vista",
		}
		if desc, ok := iisVersionMap[version]; ok {
			return fmt.Sprintf("IIS %s (%s)", version, desc)
		}
		return fmt.Sprintf("IIS %s", version)
	}
	return ""
}

// parseTomcatVersion extracts Tomcat version from Server header
func parseTomcatVersion(serverHeader string) string {
	if !strings.Contains(serverHeader, "Tomcat") {
		return ""
	}

	tomcatRegex := regexp.MustCompile(`Tomcat[/-]?([\d\.]+(?:[.-][\w]+)?)`)
	if match := tomcatRegex.FindStringSubmatch(serverHeader); match != nil {
		return fmt.Sprintf("Tomcat %s", match[1])
	}
	return ""
}

// parseNodeVersion extracts Node.js version from Server header
func parseNodeVersion(serverHeader string) string {
	nodePatterns := []string{"Node.js", "nodejs", "node", "Express"}
	isNode := false
	for _, pattern := range nodePatterns {
		if strings.Contains(serverHeader, pattern) {
			isNode = true
			break
		}
	}

	if !isNode {
		return ""
	}

	nodeRegex := regexp.MustCompile(`[\d\.]+`)
	if match := nodeRegex.FindString(serverHeader); match != "" {
		return fmt.Sprintf("Node.js/Express %s", match)
	}
	return ""
}

// parseMySQL extracts MySQL version information
func parseMySQL(banner string) (string, string) {
	// MySQL binary protocol detection
	// Banner starts with protocol version (byte 0x0a for v10)
	if len(banner) > 0 && banner[0] == 0x0a {
		// Extract version from bytes after protocol byte
		versionRegex := regexp.MustCompile(`(\d+\.\d+[\.\d\w-]*)`)
		if match := versionRegex.FindStringSubmatch(banner); match != nil {
			version := match[1]
			// Extract extra info like distribution
			if strings.Contains(banner, "MariaDB") {
				return "mysql", fmt.Sprintf("MariaDB %s", version)
			}
			if strings.Contains(banner, "Percona") {
				return "mysql", fmt.Sprintf("Percona MySQL %s", version)
			}
			return "mysql", fmt.Sprintf("MySQL %s", version)
		}
		return "mysql", "MySQL"
	}

	// Text-based detection
	if strings.Contains(banner, "MySQL") || strings.Contains(banner, "MariaDB") {
		// Pattern: "MySQL 5.7.30", "MariaDB 10.4.12", etc.
		versionRegex := regexp.MustCompile(`((?:MySQL|MariaDB|Percona)[\s-]+)([\d\.]+[\w.-]*)`)
		if match := versionRegex.FindStringSubmatch(banner); match != nil {
			service := match[1]
			version := match[2]
			// Clean up service name
			service = strings.TrimSpace(strings.Replace(service, "-", "", -1))
			return "mysql", fmt.Sprintf("%s %s", service, version)
		}
		return "mysql", ""
	}

	return "", ""
}

// parseMicrosoftServices extracts Microsoft service information
func parseMicrosoftServices(banner string) (string, string) {
	if !strings.Contains(banner, "Microsoft") {
		return "", ""
	}

	// Microsoft HTTPAPI
	if strings.Contains(banner, "Microsoft-HTTPAPI") {
		httpapiRegex := regexp.MustCompile(`Microsoft-HTTPAPI/([\d\.]+)`)
		if match := httpapiRegex.FindStringSubmatch(banner); match != nil {
			return "http", fmt.Sprintf("Microsoft HTTPAPI %s", match[1])
		}
		return "http", "Microsoft HTTPAPI"
	}

	return "", ""
}

// parseElasticsearch extracts Elasticsearch version information
func parseElasticsearch(banner string) (string, string) {
	if !strings.Contains(banner, "Elasticsearch") {
		return "", ""
	}

	// Look for version in JSON response
	// Pattern: "number":"7.10.0"
	esVersionRegex := regexp.MustCompile(`"number"\s*:\s*"([\d\.]+)"`)
	if match := esVersionRegex.FindStringSubmatch(banner); match != nil {
		version := match[1]

		// Try to determine if it's Elasticsearch or OpenSearch
		if strings.Contains(banner, "OpenSearch") {
			return "elasticsearch", fmt.Sprintf("OpenSearch %s", version)
		}

		return "elasticsearch", fmt.Sprintf("Elasticsearch %s", version)
	}

	// Fallback pattern for banner format
	esRegex := regexp.MustCompile(`Elasticsearch[\s]+([\d\.]+)`)
	if match := esRegex.FindStringSubmatch(banner); match != nil {
		return "elasticsearch", fmt.Sprintf("Elasticsearch %s", match[1])
	}

	// Generic Elasticsearch detection
	return "elasticsearch", "Elasticsearch"
}

// parseJMS extracts JMS/OpenMQ version information
func parseJMS(banner string) (string, string) {
	if !strings.Contains(banner, "imqbroker") {
		return "", ""
	}

	jmsRegex := regexp.MustCompile(`(\d+)\s*\(imqbroker\)\s*(\d+)`)
	if match := jmsRegex.FindStringSubmatch(banner); match != nil {
		return "jms", fmt.Sprintf("OpenMQ %s.%s", match[1], match[2])
	}

	return "jms", ""
}

// parseGlassFish extracts GlassFish server information
func parseGlassFish(banner string) (string, string) {
	glassfishRegex := regexp.MustCompile(`(?i)GlassFish[\s-]+([\d\.]+)`)
	if match := glassfishRegex.FindStringSubmatch(banner); match != nil {
		return "http", fmt.Sprintf("GlassFish %s", match[1])
	}
	return "", ""
}

// parseSMB extracts SMB/Windows version information
func parseSMB(banner string) (string, string) {
	// Check for various SMB detection patterns
	lowerBanner := strings.ToLower(banner)

	// Check for Samba
	if strings.Contains(lowerBanner, "samba") {
		sambaRegex := regexp.MustCompile(`(?i)samba\s+smbd?\s+([\d\.]+)`)
		if match := sambaRegex.FindStringSubmatch(banner); match != nil {
			return "microsoft-ds", fmt.Sprintf("Samba %s", match[1])
		}
		// Generic Samba patterns
		if strings.Contains(banner, "3.") {
			return "microsoft-ds", "Samba 3.X"
		} else if strings.Contains(banner, "4.") {
			return "microsoft-ds", "Samba 4.X"
		}
		return "microsoft-ds", "Samba"
	}

	// Check for Windows Server versions
	if strings.Contains(banner, "Windows") || strings.Contains(banner, "2008") || strings.Contains(banner, "2012") ||
		strings.Contains(banner, "2016") || strings.Contains(banner, "2019") {

		if strings.Contains(banner, "2008 R2") {
			return "microsoft-ds", "Windows Server 2008 R2"
		} else if strings.Contains(banner, "2008") {
			return "microsoft-ds", "Windows Server 2008"
		} else if strings.Contains(banner, "2012 R2") {
			return "microsoft-ds", "Windows Server 2012 R2"
		} else if strings.Contains(banner, "2012") {
			return "microsoft-ds", "Windows Server 2012"
		} else if strings.Contains(banner, "2016") {
			return "microsoft-ds", "Windows Server 2016"
		} else if strings.Contains(banner, "2019") {
			return "microsoft-ds", "Windows Server 2019"
		} else if strings.Contains(banner, "Windows 10") {
			return "microsoft-ds", "Windows 10"
		} else if strings.Contains(banner, "Windows 7") {
			return "microsoft-ds", "Windows 7"
		}
		return "microsoft-ds", "Microsoft Windows SMB"
	}

	// Check for explicit SMB version
	if strings.Contains(banner, "SMB") {
		smb311Regex := regexp.MustCompile(`SMB\s+(\d+\.\d+\.\d+)`)
		if match := smb311Regex.FindStringSubmatch(banner); match != nil {
			return "microsoft-ds", fmt.Sprintf("SMB %s", match[1])
		}

		smbVersionRegex := regexp.MustCompile(`SMB\s+(\d+\.\d+)`)
		if match := smbVersionRegex.FindStringSubmatch(banner); match != nil {
			return "microsoft-ds", fmt.Sprintf("SMB %s", match[1])
		}

		smbvRegex := regexp.MustCompile(`SMBv([\d\.]+)`)
		if match := smbvRegex.FindStringSubmatch(banner); match != nil {
			return "microsoft-ds", fmt.Sprintf("SMB %s", match[1])
		}

		if strings.Contains(banner, "SMB 1") {
			return "microsoft-ds", "SMB 1.0 (legacy)"
		}

		return "microsoft-ds", "SMB"
	}

	return "", ""
}

// parsePostgreSQL extracts PostgreSQL version information
func parsePostgreSQL(banner string) (string, string) {
	if !strings.Contains(banner, "PostgreSQL") {
		return "", ""
	}

	pgRegex := regexp.MustCompile(`PostgreSQL[\s]+([\d\.]+[\w.-]*)`)
	if match := pgRegex.FindStringSubmatch(banner); match != nil {
		return "postgresql", fmt.Sprintf("PostgreSQL %s", match[1])
	}
	return "postgresql", "PostgreSQL"
}

// parseRedis extracts Redis version information
func parseRedis(banner string) (string, string) {
	if !strings.Contains(banner, "redis") && !strings.Contains(banner, "Redis") {
		return "", ""
	}

	redisRegex := regexp.MustCompile(`v=([\d\.]+[\w.-]*)`)
	if match := redisRegex.FindStringSubmatch(banner); match != nil {
		return "redis", fmt.Sprintf("Redis %s", match[1])
	}
	return "redis", "Redis"
}

// parseOpenSSH extracts detailed OpenSSH version with distribution
func parseOpenSSHDetailed(banner string) (string, string) {
	if !strings.Contains(banner, "OpenSSH") {
		return "", ""
	}

	// Pattern: "OpenSSH_7.4 (Ubuntu)"
	sshRegex := regexp.MustCompile(`OpenSSH_([\d\.]+)(?:[p\d])?(?:\s*\(([^)]+)\))?`)
	if match := sshRegex.FindStringSubmatch(banner); match != nil {
		version := match[1]
		distro := match[2]

		if distro != "" {
			return "ssh", fmt.Sprintf("OpenSSH %s (%s)", version, distro)
		}
		return "ssh", fmt.Sprintf("OpenSSH %s", version)
	}
	return "", ""
}

// grabBanner is called in scanner for non-http ports or uses grabHTTPBanner
// This function determines if port should be treated as HTTP
func shouldParseAsHTTP(port int) bool {
	// Common HTTP/HTTPS ports
	httpPorts := map[int]bool{
		80:    true,
		81:    true,
		82:    true,
		83:    true,
		443:   true,
		488:   true,
		591:   true,
		631:   true,
		3000:  true,
		3001:  true,
		3005:  true,
		4000:  true,
		4343:  true,
		4848:  true,
		5000:  true,
		5353:  true,
		5357:  true,
		5672:  true,
		5985:  true,
		5986:  true,
		6080:  true,
		6081:  true,
		6443:  true,
		7000:  true,
		7001:  true,
		7080:  true,
		7443:  true,
		8000:  true,
		8001:  true,
		8008:  true,
		8009:  true,
		8010:  true,
		8011:  true,
		8019:  true,
		8020:  true,
		8021:  true,
		8042:  true,
		8080:  true,
		8081:  true,
		8082:  true,
		8083:  true,
		8084:  true,
		8085:  true,
		8086:  true,
		8087:  true,
		8088:  true,
		8089:  true,
		8090:  true,
		8091:  true,
		8092:  true,
		8093:  true,
		8097:  true,
		8099:  true,
		8100:  true,
		8180:  true,
		8181:  true,
		8191:  true,
		8192:  true,
		8200:  true,
		8222:  true,
		8254:  true,
		8290:  true,
		8291:  true,
		8292:  true,
		8383:  true,
		8443:  true,
		8444:  true,
		8445:  true,
		8500:  true,
		8600:  true,
		8649:  true,
		8651:  true,
		8652:  true,
		8654:  true,
		8686:  true,
		8765:  true,
		8800:  true,
		8873:  true,
		8888:  true,
		8899:  true,
		8994:  true,
		9000:  true,
		9001:  true,
		9002:  true,
		9003:  true,
		9008:  true,
		9009:  true,
		9010:  true,
		9011:  true,
		9040:  true,
		9050:  true,
		9071:  true,
		9080:  true,
		9081:  true,
		9090:  true,
		9091:  true,
		9099:  true,
		9110:  true,
		9111:  true,
		9200:  true,
		9290:  true,
		9443:  true,
		9502:  true,
		9503:  true,
		9618:  true,
		9666:  true,
		9898:  true,
		9900:  true,
		9917:  true,
		9943:  true,
		9944:  true,
		10000: true,
		10001: true,
		10002: true,
		10008: true,
		10009: true,
		10012: true,
		10024: true,
		10025: true,
		10160: true,
		10215: true,
		11111: true,
		11967: true,
		12345: true,
		13456: true,
		15003: true,
		16000: true,
		16001: true,
		16080: true,
		18888: true,
		19315: true,
		20000: true,
		30000: true,
		32773: true,
		32774: true,
		32775: true,
		40000: true,
		44443: true,
		44444: true,
		50389: true,
		50636: true,
		55056: true,
		55555: true,
		58080: true,
		61532: true,
		61900: true,
		62078: true,
		65000: true,
		65389: true,
	}
	return httpPorts[port]
}
