package gomap

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/NexusFireMan/gomap/v2/pkg/output"
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

	cmd := exec.Command("go", "install", ModulePath+"@latest")
	if cmdOutput, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("%s\n", output.StatusWarn(fmt.Sprintf("Installation output: %s", string(cmdOutput))))
		return fmt.Errorf("failed to install: %w", err)
	}

	binaryPath, err := resolveGoInstalledBinaryPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(binaryPath); err == nil {
		fmt.Printf("%s\n", output.StatusOK(fmt.Sprintf("gomap installed at: %s", output.Highlight(binaryPath))))

		// Try to keep the command used by the user updated (PATH can point to /usr/local/bin first).
		tryUpdateActiveBinary(binaryPath)
	}

	fmt.Println(output.StatusOK("gomap has been updated to the latest version"))
	return nil
}

func resolveGoInstalledBinaryPath() (string, error) {
	gobinCmd := exec.Command("go", "env", "GOBIN")
	if out, err := gobinCmd.Output(); err == nil {
		gobin := strings.TrimSpace(string(out))
		if gobin != "" {
			return filepath.Join(gobin, "gomap"), nil
		}
	}

	gopathCmd := exec.Command("go", "env", "GOPATH")
	if out, err := gopathCmd.Output(); err == nil {
		gopath := strings.TrimSpace(string(out))
		if gopath != "" {
			parts := filepath.SplitList(gopath)
			if len(parts) > 0 && parts[0] != "" {
				return filepath.Join(parts[0], "bin", "gomap"), nil
			}
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not determine Go bin path")
	}
	return filepath.Join(home, "go", "bin", "gomap"), nil
}

func tryUpdateActiveBinary(binaryPath string) {
	activePath, err := exec.LookPath("gomap")
	if err != nil {
		fmt.Printf("%s\n", output.StatusWarn("Could not resolve active gomap path from PATH."))
		return
	}

	activePath, _ = filepath.EvalSymlinks(activePath)
	binaryPath, _ = filepath.EvalSymlinks(binaryPath)

	if activePath == binaryPath {
		return
	}

	if err := replaceBinaryAtomically(binaryPath, activePath); err == nil {
		fmt.Printf("%s\n", output.StatusOK(fmt.Sprintf("Updated active binary: %s", output.Highlight(activePath))))
		return
	}

	if err := replaceBinaryAtomicallyWithSudo(binaryPath, activePath); err == nil {
		fmt.Printf("%s\n", output.StatusOK(fmt.Sprintf("Updated active binary with sudo: %s", output.Highlight(activePath))))
		return
	}

	// Common case: PATH prioritizes /usr/local/bin but go install writes into ~/go/bin.
	fmt.Printf("%s\n", output.StatusWarn(fmt.Sprintf("Active command still points to %s", output.Highlight(activePath))))
	fmt.Printf("%s\n", output.StatusWarn(fmt.Sprintf("Run manually: sudo install -m 0755 %s %s.new && sudo mv -f %s.new %s", binaryPath, activePath, activePath, activePath)))
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

func replaceBinaryAtomically(src, dst string) error {
	tmp := dst + ".new"
	if err := copyFile(src, tmp); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0755); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func replaceBinaryAtomicallyWithSudo(src, dst string) error {
	tmp := dst + ".new"

	installCmd := exec.Command("sudo", "install", "-m", "0755", src, tmp)
	if cmdOutput, err := installCmd.CombinedOutput(); err != nil {
		if strings.TrimSpace(string(cmdOutput)) != "" {
			fmt.Printf("%s\n", output.StatusWarn(fmt.Sprintf("sudo output: %s", strings.TrimSpace(string(cmdOutput)))))
		}
		return err
	}

	renameCmd := exec.Command("sudo", "mv", "-f", tmp, dst)
	if cmdOutput, err := renameCmd.CombinedOutput(); err != nil {
		if strings.TrimSpace(string(cmdOutput)) != "" {
			fmt.Printf("%s\n", output.StatusWarn(fmt.Sprintf("sudo output: %s", strings.TrimSpace(string(cmdOutput)))))
		}
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
	fmt.Printf("   %s\n", output.Highlight("go install github.com/NexusFireMan/gomap/v2@latest"))
	fmt.Println("\n3. Manual update:")
	fmt.Printf("   %s\n", output.Highlight("git pull origin main && go build"))
}
