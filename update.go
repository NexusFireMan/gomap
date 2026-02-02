package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	repoURL = "https://github.com/NexusFireMan/gomap"
	version = "1.0.0"
)

// CheckUpdate checks and updates the tool
func CheckUpdate() error {
	fmt.Println("Checking for updates...")

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
	fmt.Println("Detected git repository. Updating via git...")

	// Pull latest changes
	pullCmd := exec.Command("git", "pull", "origin", "main")
	if output, err := pullCmd.CombinedOutput(); err != nil {
		fmt.Printf("Git pull failed: %s\n", output)
		return fmt.Errorf("failed to pull from git: %w", err)
	}

	fmt.Println("✓ Repository updated")

	// Rebuild the project
	fmt.Println("Rebuilding gomap...")
	buildCmd := exec.Command("go", "build", "-o", "gomap")
	if output, err := buildCmd.CombinedOutput(); err != nil {
		fmt.Printf("Build failed: %s\n", output)
		return fmt.Errorf("failed to rebuild: %w", err)
	}

	fmt.Println("✓ Build successful")
	fmt.Println("✓ gomap has been updated to the latest version")
	return nil
}

// updateUsingGoInstall updates the tool using go install
func updateUsingGoInstall() error {
	fmt.Println("Installing latest version using go install...")

	cmd := exec.Command("go", "install", repoURL+"@latest")
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("Installation output: %s\n", output)
		return fmt.Errorf("failed to install: %w", err)
	}

	// Find where go installed the binary
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		gopath = filepath.Join(os.Getenv("HOME"), "go")
	}

	binaryPath := filepath.Join(gopath, "bin", "gomap")
	if _, err := os.Stat(binaryPath); err == nil {
		fmt.Printf("✓ gomap updated at: %s\n", binaryPath)
	}

	fmt.Println("✓ gomap has been updated to the latest version")
	return nil
}

// PrintVersion prints the version information
func PrintVersion() {
	fmt.Printf("gomap version %s\n", version)
	fmt.Printf("Repository: %s\n", repoURL)
}

// PrintUpdateInfo prints information about updating
func PrintUpdateInfo() {
	fmt.Println("\nUpdate methods:")
	fmt.Println("1. Using git (if cloned from repository):")
	fmt.Println("   gomap -up")
	fmt.Println("\n2. Using go install (from anywhere):")
	fmt.Println("   go install github.com/NexusFireMan/gomap@latest")
	fmt.Println("\n3. Manual update:")
	fmt.Println("   git pull origin main && go build")
}
