package gomap

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

	if err := runGoInstallLatest(false); err != nil {
		return err
	}

	binaryPath, err := resolveGoInstalledBinaryPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(binaryPath); err != nil {
		return fmt.Errorf("go install completed but binary was not found at %s", binaryPath)
	}

	installedVersion, _ := readBinaryVersion(binaryPath)
	if installedVersion == Version {
		// Go proxy can lag behind fresh tags. Retry once with direct mode.
		fmt.Printf("%s\n", output.StatusWarn("Installed version still matches current binary. Retrying with GOPROXY=direct..."))
		if err := runGoInstallLatest(true); err != nil {
			return err
		}
		installedVersion, _ = readBinaryVersion(binaryPath)
	}

	fmt.Printf("%s\n", output.StatusOK(fmt.Sprintf("gomap installed at: %s", output.Highlight(binaryPath))))
	if installedVersion != "" {
		fmt.Printf("%s\n", output.Info(fmt.Sprintf("Installed version: %s", output.Highlight(installedVersion))))
	}

	// Keep the command used by the user updated (PATH can point to /usr/local/bin first).
	if err := tryUpdateActiveBinary(binaryPath); err != nil {
		return err
	}

	fmt.Println(output.StatusOK("gomap has been updated to the latest version"))
	return nil
}

func runGoInstallLatest(useDirectProxy bool) error {
	cmd := exec.Command("go", "install", ModulePath+"@latest")
	if useDirectProxy {
		cmd.Env = append(os.Environ(), "GOPROXY=direct")
	}
	if cmdOutput, err := cmd.CombinedOutput(); err != nil {
		if strings.TrimSpace(string(cmdOutput)) != "" {
			fmt.Printf("%s\n", output.StatusWarn(fmt.Sprintf("Installation output: %s", strings.TrimSpace(string(cmdOutput)))))
		}
		if useDirectProxy {
			return fmt.Errorf("failed to install with GOPROXY=direct: %w", err)
		}
		return fmt.Errorf("failed to install: %w", err)
	}
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

func tryUpdateActiveBinary(binaryPath string) error {
	activePath, err := exec.LookPath("gomap")
	if err != nil {
		// No active binary in PATH; install in Go bin is still useful.
		fmt.Printf("%s\n", output.StatusWarn("Could not resolve active gomap path from PATH; keeping Go bin installation only."))
		return nil
	}

	activePath, _ = filepath.EvalSymlinks(activePath)
	binaryPath, _ = filepath.EvalSymlinks(binaryPath)

	if activePath == binaryPath {
		return nil
	}

	if err := replaceBinaryAtomically(binaryPath, activePath); err == nil {
		fmt.Printf("%s\n", output.StatusOK(fmt.Sprintf("Updated active binary: %s", output.Highlight(activePath))))
		return nil
	}

	if err := replaceBinaryAtomicallyWithSudo(binaryPath, activePath); err == nil {
		fmt.Printf("%s\n", output.StatusOK(fmt.Sprintf("Updated active binary with sudo: %s", output.Highlight(activePath))))
		return nil
	}

	// Common case: PATH prioritizes /usr/local/bin but go install writes into ~/go/bin.
	fmt.Printf("%s\n", output.StatusWarn(fmt.Sprintf("Active command still points to %s", output.Highlight(activePath))))
	fmt.Printf("%s\n", output.StatusWarn(fmt.Sprintf("Run manually: sudo install -m 0755 %s %s.new && sudo mv -f %s.new %s", binaryPath, activePath, activePath, activePath)))
	return fmt.Errorf("could not replace active gomap binary at %s", activePath)
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
	installCmd.Stdin = os.Stdin
	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr
	if err := installCmd.Run(); err != nil {
		return err
	}

	renameCmd := exec.Command("sudo", "mv", "-f", tmp, dst)
	renameCmd.Stdin = os.Stdin
	renameCmd.Stdout = os.Stdout
	renameCmd.Stderr = os.Stderr
	if err := renameCmd.Run(); err != nil {
		return err
	}
	return nil
}

var versionRegex = regexp.MustCompile(`(?m)^gomap version ([^ \n\r\t]+)`)

func readBinaryVersion(path string) (string, error) {
	cmd := exec.Command(path, "-v")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	matches := versionRegex.FindStringSubmatch(string(out))
	if len(matches) != 2 {
		return "", fmt.Errorf("could not parse version output from %s", path)
	}
	return strings.TrimSpace(matches[1]), nil
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
