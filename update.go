package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	repoURL = "https://github.com/NexusFireMan/gomap"
	version = "2.0.1"
)

// CheckUpdate checks and updates the tool
func CheckUpdate() error {
	fmt.Println(Info("🔄 Checking for updates..."))

	// Try to update using git pull if in a git repository
	if isGitRepository() {
		return updateUsingGit()
	}

	// Otherwise, try using go install
	return updateUsingGoInstall()
}

// isGitRepository checks if the current directory is a git repository
func isGitRepository() bool {
	cmd := exec.Command("git", "rev-parse", "--git-dir")
	return cmd.Run() == nil
}

// updateUsingGit updates the tool using git pull and rebuilds
func updateUsingGit() error {
	fmt.Println(Success("✓ Detected git repository. Updating via git..."))

	// Pull latest changes
	pullCmd := exec.Command("git", "pull", "origin", "main")
	if output, err := pullCmd.CombinedOutput(); err != nil {
		fmt.Printf("%s\n", StatusError(fmt.Sprintf("Git pull failed: %s", string(output))))
		return fmt.Errorf("failed to pull from git: %w", err)
	}

	fmt.Println(StatusOK("Repository updated"))

	// Rebuild the project
	fmt.Println(Info("🔨 Rebuilding gomap..."))
	buildCmd := exec.Command("go", "build", "-o", "gomap")
	if output, err := buildCmd.CombinedOutput(); err != nil {
		fmt.Printf("%s\n", StatusError(fmt.Sprintf("Build failed: %s", string(output))))
		return fmt.Errorf("failed to rebuild: %w", err)
	}

	fmt.Println(StatusOK("Build successful"))
	fmt.Println(StatusOK("gomap has been updated to the latest version"))
	return nil
}

// updateUsingGoInstall updates the tool using go install
func updateUsingGoInstall() error {
	fmt.Println(Info("📦 Installing latest version using go install..."))

	cmd := exec.Command("go", "install", repoURL+"@latest")
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("%s\n", StatusWarn(fmt.Sprintf("Installation output: %s", string(output))))
		return fmt.Errorf("failed to install: %w", err)
	}

	// Find where go installed the binary
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		gopath = filepath.Join(os.Getenv("HOME"), "go")
	}

	binaryPath := filepath.Join(gopath, "bin", "gomap")
	if _, err := os.Stat(binaryPath); err == nil {
		fmt.Printf("%s\n", StatusOK(fmt.Sprintf("gomap installed at: %s", Highlight(binaryPath))))

		// Try to install to system path
		installToSystemPath(binaryPath)
	}

	fmt.Println(StatusOK("gomap has been updated to the latest version"))
	return nil
}

// installToSystemPath attempts to install the binary to a system PATH location
func installToSystemPath(binaryPath string) {
	systemPaths := []string{"/usr/local/bin", "/usr/bin"}

	for _, sysPath := range systemPaths {
		if err := copyFile(binaryPath, filepath.Join(sysPath, "gomap")); err == nil {
			fmt.Printf("%s\n", StatusOK(fmt.Sprintf("Also installed to: %s/gomap", sysPath)))
			return
		}
	}

	// Fallback: inform user to add to PATH
	fmt.Printf("%s\n", StatusWarn(fmt.Sprintf("To use 'gomap' command globally, add to PATH: export PATH=$PATH:%s/bin", filepath.Dir(binaryPath))))
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	if err := os.WriteFile(dst, input, 0755); err != nil {
		return err
	}

	return nil
}

// PrintVersion prints the version information
func PrintVersion() {
	fmt.Printf("%s\n", Highlight(fmt.Sprintf("gomap version %s", version)))
	fmt.Printf("%s\n", Info(fmt.Sprintf("Repository: %s", repoURL)))
}

// PrintUpdateInfo prints information about updating
func PrintUpdateInfo() {
	fmt.Println("\n" + Bold("Update methods:"))
	fmt.Println("1. Using git (if cloned from repository):")
	fmt.Printf("   %s\n", Highlight("gomap -up"))
	fmt.Println("\n2. Using go install (from anywhere):")
	fmt.Printf("   %s\n", Highlight("go install github.com/NexusFireMan/gomap@latest"))
	fmt.Println("\n3. Manual update:")
	fmt.Printf("   %s\n", Highlight("git pull origin main && go build"))
}
