package main

import (
	"testing"
)

// TestSMBBannerParsing tests the SMB banner parsing function
func TestSMBBannerParsing(t *testing.T) {
	tests := []struct {
		name    string
		banner  string
		service string
		version string
	}{
		{
			name:    "SMBv3.1.1",
			banner:  "Microsoft Windows SMB - SMBv3.1.1",
			service: "microsoft-ds",
			version: "SMBv3.1.1",
		},
		{
			name:    "SMBv2.1",
			banner:  "Microsoft Windows SMB - SMBv2.1",
			service: "microsoft-ds",
			version: "SMBv2.1",
		},
		{
			name:    "SMBv1 Legacy",
			banner:  "Microsoft Windows SMB - SMBv1 (Legacy)",
			service: "microsoft-ds",
			version: "SMBv1 (Legacy)",
		},
		{
			name:    "Generic SMB",
			banner:  "Microsoft Windows SMB",
			service: "microsoft-ds",
			version: "Windows SMB",
		},
		{
			name:    "Non-SMB",
			banner:  "Not SMB",
			service: "",
			version: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, version := parseSMB(test.banner)
			if service != test.service {
				t.Errorf("Expected service '%s', got '%s'", test.service, service)
			}
			if version != test.version {
				t.Errorf("Expected version '%s', got '%s'", test.version, version)
			}
		})
	}
}
