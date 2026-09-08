package scanner

import "testing"

func TestExpandCIDRRejectsOversizedRanges(t *testing.T) {
	for _, cidr := range []string{"::/0", "2001:db8::/64", "2001:db8::/65", "10.0.0.0/8"} {
		if _, err := ExpandCIDR(cidr); err == nil {
			t.Errorf("expected size error for %s", cidr)
		}
	}
}

func TestExpandCIDRIPv6PreservesEndpoints(t *testing.T) {
	ips, err := ExpandCIDR("2001:db8::/126")
	if err != nil || len(ips) != 4 || ips[0] != "2001:db8::" || ips[3] != "2001:db8::3" {
		t.Fatalf("unexpected IPv6 expansion: %v, %v", ips, err)
	}
}

func TestExpandCIDRLiteralIPv4(t *testing.T) {
	ips, err := ExpandCIDR("127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 || ips[0] != "127.0.0.1" {
		t.Fatalf("unexpected ips: %#v", ips)
	}
}
