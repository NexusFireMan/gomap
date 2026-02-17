package scanner

import "testing"

func TestExpandCIDRLiteralIPv4(t *testing.T) {
	ips, err := ExpandCIDR("127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 || ips[0] != "127.0.0.1" {
		t.Fatalf("unexpected ips: %#v", ips)
	}
}
