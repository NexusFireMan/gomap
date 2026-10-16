package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"runtime"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

const maxSNMPConfigBytes = 64 * 1024

var errSNMPConfig = errors.New("invalid --snmp-config: require a private regular JSON file with supported per-IP credentials")

func loadSNMPConfig(path, outputPath string) (map[string]*scanner.SNMPCredentials, error) {
	if path == "" {
		return nil, nil
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, errSNMPConfig
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errSNMPConfig
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(before, info) || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return nil, errSNMPConfig
	}
	if other, err := os.Stat(outputPath); err == nil && os.SameFile(info, other) {
		return nil, errSNMPConfig
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSNMPConfigBytes+1))
	if err != nil {
		return nil, errSNMPConfig
	}
	return parseSNMPConfig(data)
}

func parseSNMPConfig(data []byte) (map[string]*scanner.SNMPCredentials, error) {
	if len(data) > maxSNMPConfigBytes {
		return nil, errSNMPConfig
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errSNMPConfig
	}
	result := make(map[string]*scanner.SNMPCredentials)
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, errSNMPConfig
		}
		name, ok := key.(string)
		if !ok {
			return nil, errSNMPConfig
		}
		ip, err := netip.ParseAddr(name)
		if err != nil || ip.Zone() != "" {
			return nil, errSNMPConfig
		}
		name = ip.Unmap().String()
		if _, exists := result[name]; exists {
			return nil, errSNMPConfig
		}
		start, err := dec.Token()
		if err != nil || start != json.Delim('{') {
			return nil, errSNMPConfig
		}
		fields := make(map[string]string)
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return nil, errSNMPConfig
			}
			keyName, ok := key.(string)
			if !ok {
				return nil, errSNMPConfig
			}
			switch keyName {
			case "username", "auth_protocol", "auth_password", "privacy_protocol", "privacy_password":
			default:
				return nil, errSNMPConfig
			}
			if _, duplicate := fields[keyName]; duplicate {
				return nil, errSNMPConfig
			}
			var value *string
			if err := dec.Decode(&value); err != nil || value == nil {
				return nil, errSNMPConfig
			}
			fields[keyName] = *value
		}
		if _, err := dec.Token(); err != nil {
			return nil, errSNMPConfig
		}
		credentials, err := scanner.NewSNMPCredentials(fields["username"], fields["auth_protocol"], fields["auth_password"], fields["privacy_protocol"], fields["privacy_password"])
		if err != nil {
			return nil, errSNMPConfig
		}
		result[name] = credentials
	}
	if _, err := dec.Token(); err != nil || len(result) == 0 {
		return nil, errSNMPConfig
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errSNMPConfig
	}
	return result, nil
}

func validateSNMPScope(config map[string]*scanner.SNMPCredentials, targets []string) error {
	if len(config) == 0 {
		return nil
	}
	wanted := make(map[string]bool, len(targets))
	for _, target := range targets {
		if ip, err := netip.ParseAddr(target); err == nil {
			wanted[ip.Unmap().String()] = true
		}
	}
	for ip := range config {
		if !wanted[ip] {
			return errors.New("--snmp-config contains an IP outside the expanded target scope")
		}
	}
	return nil
}
