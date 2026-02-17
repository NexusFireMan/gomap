package gomap

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/NexusFireMan/gomap/pkg/output"
)

// CheckUpdate checks and updates the tool
func CheckUpdate() error {
	fmt.Println(output.Info("🔄 Checking for updates..."))

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
	fmt.Println(output.Success("✓ Detected git repository. Updating via git..."))

	// Pull latest changes
	pullCmd := exec.Command("git", "pull", "origin", "main")
	if cmdOutput, err := pullCmd.CombinedOutput(); err != nil {
		fmt.Printf("%s\n", output.StatusError(fmt.Sprintf("Git pull failed: %s", string(cmdOutput))))
		return fmt.Errorf("failed to pull from git: %w", err)
	}

	fmt.Println(output.StatusOK("Repository updated"))

	// Clean Go cache to ensure fresh build from scratch
	fmt.Println(output.Info("🧹 Cleaning Go build cache..."))
	cleanCmd := exec.Command("go", "clean", "-cache")
	_ = cleanCmd.Run() // Ignore errors, cache might already be clean

	// Rebuild the project with -a flag to force full rebuild
	fmt.Println(output.Info("🔨 Rebuilding gomap..."))
	buildCmd := exec.Command("go", "build", "-a", "-o", "gomap")
	if cmdOutput, err := buildCmd.CombinedOutput(); err != nil {
		fmt.Printf("%s\n", output.StatusError(fmt.Sprintf("Build failed: %s", string(cmdOutput))))
		return fmt.Errorf("failed to rebuild: %w", err)
	}

	fmt.Println(output.StatusOK("Build successful"))
	fmt.Println(output.StatusOK("gomap has been updated to the latest version"))
	return nil
}

// updateUsingGoInstall updates the tool using go install
func updateUsingGoInstall() error {
	fmt.Println(output.Info("📦 Installing latest version using go install..."))

	cmd := exec.Command("go", "install", RepoURL+"@latest")
	if cmdOutput, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("%s\n", output.StatusWarn(fmt.Sprintf("Installation output: %s", string(cmdOutput))))
		return fmt.Errorf("failed to install: %w", err)
	}

	// Find where go installed the binary
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		gopath = filepath.Join(os.Getenv("HOME"), "go")
	}

	binaryPath := filepath.Join(gopath, "bin", "gomap")
	if _, err := os.Stat(binaryPath); err == nil {
		fmt.Printf("%s\n", output.StatusOK(fmt.Sprintf("gomap installed at: %s", output.Highlight(binaryPath))))

		// Try to install to system path
		installToSystemPath(binaryPath)
	}

	fmt.Println(output.StatusOK("gomap has been updated to the latest version"))
	return nil
}

// installToSystemPath attempts to install the binary to /usr/local/bin for system-wide access
func installToSystemPath(binaryPath string) {
	systemPath := "/usr/local/bin"
	destPath := filepath.Join(systemPath, "gomap")

	// Try to copy with sudo
	cmd := exec.Command("sudo", "cp", binaryPath, destPath)
	if err := cmd.Run(); err == nil {
		fmt.Printf("%s\n", output.StatusOK(fmt.Sprintf("Also installed to: %s (system-wide access)", destPath)))

		// Make sure it's executable
		_ = exec.Command("sudo", "chmod", "+x", destPath).Run()
		return
	}

	// Try without sudo if direct access works
	if err := copyFile(binaryPath, destPath); err == nil {
		fmt.Printf("%s\n", output.StatusOK(fmt.Sprintf("Also installed to: %s (system-wide access)", destPath)))
		return
	}

	// Fallback: inform user
	fmt.Printf("%s\n", output.StatusWarn(fmt.Sprintf("To install system-wide, run: sudo cp %s %s", binaryPath, destPath)))
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
	fmt.Printf("%s\n", output.Highlight(fmt.Sprintf("gomap version %s", Version)))
	fmt.Printf("%s\n", output.Info(fmt.Sprintf("Repository: %s", RepoURL)))
	fmt.Printf("%s\n", output.Info(fmt.Sprintf("Commit: %s", Commit)))
	fmt.Printf("%s\n", output.Info(fmt.Sprintf("Build date: %s", Date)))
}

// PrintUpdateInfo prints information about updating
func PrintUpdateInfo() {
	fmt.Println("\n" + output.Bold("Update methods:"))
	fmt.Println("1. Using git (if cloned from repository):")
	fmt.Printf("   %s\n", output.Highlight("gomap -up"))
	fmt.Println("\n2. Using go install (from anywhere):")
	fmt.Printf("   %s\n", output.Highlight("go install github.com/NexusFireMan/gomap@latest"))
	fmt.Println("\n3. Manual update:")
	fmt.Printf("   %s\n", output.Highlight("git pull origin main && go build"))
}
