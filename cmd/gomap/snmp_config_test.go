package gomap

import "testing"

func TestCLISNMPConfigOptIn(t *testing.T) {
	opts, err := ParseCLIOptions([]string{"127.0.0.1", "-u", "--snmp-config", "private.json"})
	if err != nil || opts.SNMPConfig != "private.json" || !opts.ServiceFlag {
		t.Fatalf("invalid options: %+v %v", opts, err)
	}
	for _, args := range [][]string{
		{"--snmp-config", "private.json", "127.0.0.1"},
		{"-u", "--snmp-config", " ", "127.0.0.1"},
		{"-u", "-g", "--snmp-config", "private.json", "127.0.0.1"},
		{"-u", "--random-ip", "--snmp-config", "private.json", "127.0.0.1"},
	} {
		if _, err := ParseCLIOptions(args); err == nil {
			t.Fatal("incompatible credential mode accepted")
		}
	}
}
