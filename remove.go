package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// RemoveGomap removes gomap from the system
func RemoveGomap() error {
	fmt.Println(Warning("⚠ Removing gomap from your system..."))
	fmt.Println("")

	// Try to remove from /usr/local/bin first (primary location)
	if removed := tryRemoveFromPath("/usr/local/bin/gomap"); removed {
		fmt.Println(Success("✓ gomap successfully removed from /usr/local/bin/"))
		return nil
	}

	// Try home directory bin
	homeDir, err := os.UserHomeDir()
	if err == nil {
		homeBinPath := filepath.Join(homeDir, "bin", "gomap")
		if removed := tryRemoveFromPath(homeBinPath); removed {
			fmt.Println(Success("✓ gomap successfully removed from ~/bin/"))
			return nil
		}
	}

	// Try to find and remove from GOPATH
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		gopath = filepath.Join(homeDir, "go")
	}
	gopathBin := filepath.Join(gopath, "bin", "gomap")
	if removed := tryRemoveFromPath(gopathBin); removed {
		fmt.Println(Success("✓ gomap successfully removed from GOPATH/bin/"))
		return nil
	}

	// If we reach here, we couldn't find the binary to remove
	fmt.Println(Warning("⚠ Could not find gomap installation in common locations"))
	fmt.Println(Info("ℹ Common locations:"))
	fmt.Println(Info("  - /usr/local/bin/gomap (system-wide)"))
	fmt.Println(Info("  - ~/bin/gomap (user)"))
	fmt.Println(Info("  - $GOPATH/bin/gomap (Go binaries)"))
	fmt.Println("")
	fmt.Println(Info("To manually remove, find and delete the gomap binary:"))
	fmt.Println(Info("  which gomap     # Find location"))
	fmt.Println(Info("  rm <location>   # Remove it"))

	return fmt.Errorf("gomap not found in standard locations")
}

// tryRemoveFromPath attempts to remove gomap from a specific path
func tryRemoveFromPath(path string) bool {
	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}

	// Try to remove with user's current permissions first
	if err := os.Remove(path); err == nil {
		return true
	}

	// If permission denied, try with sudo
	if os.Geteuid() != 0 { // Not running as root
		fmt.Println(Info("🔐 Requesting sudo to remove system-wide installation..."))

		cmd := exec.Command("sudo", "rm", "-f", path)
		if err := cmd.Run(); err == nil {
			return true
		}

		// Try sudo without password prompt (if available)
		cmd = exec.Command("sudo", "-n", "rm", "-f", path)
		if err := cmd.Run(); err == nil {
			return true
		}
	} else {
		// Running as root, just remove directly
		if err := os.Remove(path); err == nil {
			return true
		}
	}

	return false
}
