package scanner

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

func TestParseSMBClientOutputSambaServerComment(t *testing.T) {
	out := `smbXcli_negprot_smb1_done: No compatible protocol selected by server.
Disk|print$|Printer Drivers
Disk|sambashare|InFreight SMB v3.1
IPC|IPC$|IPC Service (InlaneFreight SMB server (Samba, Ubuntu))
`
	got := parseSMBClientOutput(out)
	if got != "InlaneFreight SMB server (Samba, Ubuntu)" {
		t.Fatalf("unexpected smbclient parse: %q", got)
	}
}

func TestParseRPCClientSrvInfoSambaServerComment(t *testing.T) {
	out := `DEVSMB         Wk Sv PrQ Unx NT SNT InlaneFreight SMB server (Samba, Ubuntu)
platform_id     : 500
os version      : 6.1
server type     : 0x809a03
`
	got := parseRPCClientSrvInfo(out)
	if got != "InlaneFreight SMB server (Samba, Ubuntu)" {
		t.Fatalf("unexpected rpcclient parse: %q", got)
	}
}

func TestParseNmapSMBProtocols(t *testing.T) {
	out := `| smb-protocols:
|   dialects:
|     2.0.2
|     2.1
|     3.0
|_    3.1.1
`
	got := parseNmapSMBProtocols(out)
	if got != "SMB 2.0.2-3.1.1" {
		t.Fatalf("unexpected nmap protocols parse: %q", got)
	}
}
