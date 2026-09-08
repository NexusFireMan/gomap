package gomap

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGitUpdateOnlyRecognizesGoMapRoot(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	dir := t.TempDir()
	t.Chdir(dir)
	if out, err := exec.Command("git", "init", "-b", "feature-test").CombinedOutput(); err != nil {
		t.Fatalf("git init: %s: %v", out, err)
	}
	if err := os.WriteFile("go.mod", []byte("module example.invalid/other\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if isGitRepository() {
		t.Fatal("unrelated repository accepted for update")
	}
	if err := os.WriteFile("go.mod", []byte("module "+ModulePath+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if !isGitRepository() {
		t.Fatal("GoMap root not recognized")
	}
	if err := updateUsingGit(); err == nil {
		t.Fatal("feature branch update should fail before pull")
	}
}

func TestReleaseDownloadRequiresChecksums(t *testing.T) {
	for _, url := range []string{"", "https://example.invalid/checksums.txt"} {
		called := false
		err := verifyReleaseDownload(filepath.Join(t.TempDir(), "gomap.tar.gz"), "gomap.tar.gz", url, func(string, string) error {
			called = true
			return errors.New("download failed")
		})
		if err == nil || called != (url != "") {
			t.Fatalf("url=%q: expected verification failure, got %v (download called=%v)", url, err, called)
		}
	}
}

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
