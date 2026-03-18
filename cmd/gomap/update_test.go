package gomap

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReadBinaryVersionCurrentFormat(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script test is unix-oriented")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "gomap")
	script := "#!/bin/sh\ncat <<'EOF'\n\033[1mVersion\033[0m\n  gomap:      \033[96m2.4.3\033[0m\n  repository: https://github.com/NexusFireMan/gomap\nEOF\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}

	version, err := readBinaryVersion(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != "2.4.3" {
		t.Fatalf("expected version 2.4.3, got %q", version)
	}
}
