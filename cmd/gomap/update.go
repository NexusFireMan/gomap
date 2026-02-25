package gomap

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/NexusFireMan/gomap/v2/pkg/output"
)

// CheckUpdate checks and updates the tool
func CheckUpdate() error {
	fmt.Println(output.Info("🔄 Checking for updates..."))

	// Try to update using git pull if in a git repository
	if isGitRepository() {
		return updateUsingGit()
	}

	// Prefer release asset update (includes embedded metadata), fallback to go install.
	if err := updateUsingReleaseAsset(); err == nil {
		return nil
	} else {
		fmt.Printf("%s\n", output.StatusWarn(fmt.Sprintf("Release binary update failed: %v", err)))
		fmt.Printf("%s\n", output.StatusWarn("Falling back to go install..."))
	}
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
	commitOut, _ := exec.Command("git", "rev-parse", "--short=12", "HEAD").Output()
	buildCommit := strings.TrimSpace(string(commitOut))
	if buildCommit == "" {
		buildCommit = "unknown"
	}
	buildDate := time.Now().UTC().Format(time.RFC3339)
	ldflags := fmt.Sprintf("-s -w -X %s/cmd/gomap.Version=%s -X %s/cmd/gomap.Commit=%s -X %s/cmd/gomap.Date=%s",
		ModulePath, Version, ModulePath, buildCommit, ModulePath, buildDate)
	buildCmd := exec.Command("go", "build", "-a", "-ldflags", ldflags, "-o", "gomap")
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

type githubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func updateUsingReleaseAsset() error {
	fmt.Println(output.Info("📦 Installing latest release binary..."))

	rel, err := fetchLatestRelease()
	if err != nil {
		return err
	}

	archiveName, archiveURL, checksumURL := pickReleaseAssets(rel)
	if archiveURL == "" {
		return fmt.Errorf("no compatible release asset found for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	tmpDir, err := os.MkdirTemp("", "gomap-update-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	archivePath := filepath.Join(tmpDir, archiveName)
	if err := downloadFile(archiveURL, archivePath); err != nil {
		return fmt.Errorf("failed to download release asset: %w", err)
	}

	if checksumURL != "" {
		checksumPath := filepath.Join(tmpDir, "checksums.txt")
		if err := downloadFile(checksumURL, checksumPath); err == nil {
			if err := verifyChecksum(archivePath, archiveName, checksumPath); err != nil {
				return fmt.Errorf("checksum verification failed: %w", err)
			}
		}
	}

	binPath := filepath.Join(tmpDir, "gomap")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	if err := extractBinaryFromArchive(archivePath, binPath); err != nil {
		return fmt.Errorf("failed to extract binary: %w", err)
	}
	_ = os.Chmod(binPath, 0o755)

	installedVersion, _ := readBinaryVersion(binPath)
	fmt.Printf("%s\n", output.StatusOK(fmt.Sprintf("Downloaded release %s asset: %s", rel.TagName, archiveName)))
	if installedVersion != "" {
		fmt.Printf("%s\n", output.Info(fmt.Sprintf("Release binary version: %s", output.Highlight(installedVersion))))
	}

	if err := tryUpdateActiveBinary(binPath); err != nil {
		return err
	}

	fmt.Println(output.StatusOK("gomap has been updated to the latest release binary"))
	return nil
}

func fetchLatestRelease() (githubRelease, error) {
	var rel githubRelease
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/repos/NexusFireMan/gomap/releases/latest", nil)
	if err != nil {
		return rel, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "gomap-updater")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return rel, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return rel, fmt.Errorf("github api responded %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return rel, err
	}
	return rel, nil
}

func pickReleaseAssets(rel githubRelease) (archiveName, archiveURL, checksumURL string) {
	expectedCore := "_" + runtime.GOOS + "_" + runtime.GOARCH
	expectedExt := ".tar.gz"
	if runtime.GOOS == "windows" {
		expectedExt = ".zip"
	}

	for _, a := range rel.Assets {
		switch {
		case a.Name == "checksums.txt":
			checksumURL = a.BrowserDownloadURL
		case strings.Contains(a.Name, expectedCore) && strings.HasSuffix(a.Name, expectedExt):
			archiveName = a.Name
			archiveURL = a.BrowserDownloadURL
		}
	}
	return archiveName, archiveURL, checksumURL
}

func downloadFile(url, dst string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "gomap-updater")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: %s", resp.Status)
	}

	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	return nil
}

func verifyChecksum(archivePath, archiveName, checksumsPath string) error {
	data, err := os.ReadFile(checksumsPath)
	if err != nil {
		return err
	}

	var expected string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[len(parts)-1] == archiveName {
			expected = parts[0]
			break
		}
	}
	if expected == "" {
		return fmt.Errorf("checksum not found for %s", archiveName)
	}

	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return err
	}
	actual := hex.EncodeToString(sum.Sum(nil))
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expected, actual)
	}
	return nil
}

func extractBinaryFromArchive(archivePath, dstBinary string) error {
	if strings.HasSuffix(archivePath, ".zip") {
		return extractBinaryFromZip(archivePath, dstBinary)
	}
	if strings.HasSuffix(archivePath, ".tar.gz") {
		return extractBinaryFromTarGz(archivePath, dstBinary)
	}
	return fmt.Errorf("unsupported archive format: %s", archivePath)
}

func extractBinaryFromTarGz(archivePath, dstBinary string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := filepath.Base(hdr.Name)
		if name == "gomap" || name == "gomap.exe" {
			outFile, err := os.Create(dstBinary)
			if err != nil {
				return err
			}
			defer func() { _ = outFile.Close() }()
			if _, err := io.Copy(outFile, tr); err != nil {
				return err
			}
			return nil
		}
	}
	return fmt.Errorf("gomap binary not found in tar.gz")
}

func extractBinaryFromZip(archivePath, dstBinary string) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = zr.Close() }()

	for _, f := range zr.File {
		name := filepath.Base(f.Name)
		if name == "gomap" || name == "gomap.exe" {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			defer func() { _ = rc.Close() }()

			outFile, err := os.Create(dstBinary)
			if err != nil {
				return err
			}
			defer func() { _ = outFile.Close() }()
			if _, err := io.Copy(outFile, rc); err != nil {
				return err
			}
			return nil
		}
	}
	return fmt.Errorf("gomap binary not found in zip")
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
	output.PrintBanner()
	version, commit, date := EffectiveBuildInfo()
	fmt.Printf("%s\n", output.Bold("Version"))
	fmt.Printf("  gomap:      %s\n", output.Highlight(version))
	fmt.Printf("  repository: %s\n", output.Info(RepoURL))
	fmt.Printf("  module:     %s\n", output.Info(ModulePath))
	fmt.Printf("%s\n", output.Bold("Build"))
	fmt.Printf("  commit:     %s\n", output.Info(commit))
	fmt.Printf("  date:       %s\n", output.Info(date))
}

// PrintUpdateInfo prints information about updating
func PrintUpdateInfo() {
	fmt.Println("\n" + output.Bold("Update methods:"))
	fmt.Println("1. Built-in updater (recommended):")
	fmt.Printf("   %s\n", output.Highlight("gomap -up"))
	fmt.Println("   (downloads latest release binary with checksum verification)")
	fmt.Println("\n2. Using git (if cloned from repository):")
	fmt.Printf("   %s\n", output.Highlight("gomap -up"))
	fmt.Println("\n3. Using go install (from anywhere):")
	fmt.Printf("   %s\n", output.Highlight("go install github.com/NexusFireMan/gomap/v2@latest"))
	fmt.Println("\n4. Manual update:")
	fmt.Printf("   %s\n", output.Highlight("git pull origin main && go build"))
}
