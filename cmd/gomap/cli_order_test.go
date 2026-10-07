package gomap

import "testing"

func TestCLIInterspersedOptions(t *testing.T) {
	for _, args := range [][]string{
		{"127.0.0.1", "-s", "-p", "-", "--timeout=120"},
		{"-s", "127.0.0.1", "-p", "-", "--timeout", "120"},
	} {
		opts, err := ParseCLIOptions(args)
		if err != nil || opts.Host != "127.0.0.1" || !opts.ServiceFlag || opts.PortsFlag != "-" || opts.TimeoutMS != 120 {
			t.Fatalf("%v: got %+v, %v", args, opts, err)
		}
	}
}

func TestCLILongVersion(t *testing.T) {
	opts, err := ParseCLIOptions([]string{"--version"})
	if err != nil || !opts.VersionFlag {
		t.Fatalf("got %+v, %v", opts, err)
	}
}

func TestCLITerminatorKeepsLiteralArguments(t *testing.T) {
	if _, err := ParseCLIOptions([]string{"127.0.0.1", "--", "-s"}); err == nil {
		t.Fatal("two literal targets should be rejected")
	}
}
