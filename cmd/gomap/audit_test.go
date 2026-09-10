package gomap

import (
	"strconv"
	"testing"
)

func TestCLIRejectsConflictingNegativeTopAlias(t *testing.T) {
	if _, err := ParseCLIOptions([]string{"--top=-1", "--top-ports=5", "127.0.0.1"}); err == nil {
		t.Fatal("negative --top was hidden by alias")
	}
}

func TestCLIRejectsDurationOverflow(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("duration overflow value exceeds 32-bit int")
	}
	for _, flag := range []string{"--timeout", "--max-timeout", "--backoff-ms"} {
		if _, err := ParseCLIOptions([]string{flag, "9223372036854775807", "127.0.0.1"}); err == nil {
			t.Fatalf("%s overflow accepted", flag)
		}
	}
}
