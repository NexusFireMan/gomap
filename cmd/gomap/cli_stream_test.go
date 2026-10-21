package gomap

import "testing"

func TestCLIStreamValidation(t *testing.T) {
	for _, tc := range []struct {
		args  []string
		valid bool
	}{
		{[]string{"127.0.0.1", "--stream"}, true},
		{[]string{"--stream", "-Dv", "--format", "jsonl", "127.0.0.1"}, true},
		{[]string{"--stream", "--json", "127.0.0.1"}, false},
		{[]string{"--stream", "--csv", "127.0.0.1"}, false},
		{[]string{"--stream", "-u", "127.0.0.1"}, false},
		{[]string{"--stream", "--scan-type", "syn", "127.0.0.1"}, false},
	} {
		opts, err := ParseCLIOptions(tc.args)
		if (err == nil) != tc.valid || (tc.valid && !opts.Stream) {
			t.Fatalf("args=%v opts=%+v err=%v", tc.args, opts, err)
		}
	}
}
