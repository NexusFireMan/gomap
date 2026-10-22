package gomap

import "testing"

func TestCLIRecoverTimeouts(t *testing.T) {
	if opts, err := ParseCLIOptions([]string{"127.0.0.1"}); err != nil || opts.RecoverTimeouts {
		t.Fatal("recovery default changed")
	}
	for _, tc := range []struct {
		args []string
		ok   bool
	}{
		{[]string{"--recover-timeouts", "127.0.0.1"}, true},
		{[]string{"127.0.0.1", "--recover-timeouts", "--stream", "--format", "jsonl"}, true},
		{[]string{"--recover-timeouts", "-s", "-Dv", "127.0.0.1"}, true},
		{[]string{"--recover-timeouts", "-u", "127.0.0.1"}, false},
		{[]string{"--recover-timeouts", "-g", "127.0.0.1"}, false},
		{[]string{"--recover-timeouts", "--scan-type", "syn", "127.0.0.1"}, false},
	} {
		opts, err := ParseCLIOptions(tc.args)
		if (err == nil) != tc.ok || (tc.ok && !opts.RecoverTimeouts) {
			t.Fatalf("args=%v opts=%+v err=%v", tc.args, opts, err)
		}
	}
}
