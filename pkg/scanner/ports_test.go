package scanner

import "testing"

func TestServiceMapIncludesWindowsAndAJPPorts(t *testing.T) {
	pm := NewPortManager()

	tests := map[int]string{
		8009:  "ajp13",
		8080:  "http-proxy",
		47001: "winrm",
		5985:  "winrm",
		5986:  "winrm",
	}

	for port, expected := range tests {
		got := pm.GetServiceName(port, "")
		if got != expected {
			t.Fatalf("port %d: expected %q, got %q", port, expected, got)
		}
	}
}

func TestTopPortsIncludes47001(t *testing.T) {
	ports := GetTop1000Ports()
	found := false
	for _, p := range ports {
		if p == 47001 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected top ports list to include 47001")
	}
}

func TestTopPortsHasNoDuplicates(t *testing.T) {
	ports := GetTop1000Ports()
	seen := make(map[int]struct{}, len(ports))
	for _, p := range ports {
		if _, ok := seen[p]; ok {
			t.Fatalf("duplicate port found in top list: %d", p)
		}
		seen[p] = struct{}{}
	}
}
