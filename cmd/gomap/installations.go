package gomap

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/NexusFireMan/gomap/v2/pkg/output"
)

type gomapInstallation struct {
	Path             string
	DisplayPath      string
	Active           bool
	Exists           bool
	Version          string
	PackageManaged   bool
	PackageName      string
	ProbableSource   string
	RemovalSupported bool
}

func RunDoctor() error {
	output.PrintBanner()
	fmt.Printf("%s\n", output.Bold("Doctor"))

	installs, err := detectGomapInstallations()
	if err != nil {
		return err
	}
	if len(installs) == 0 {
		fmt.Printf("%s\n", output.StatusWarn("No gomap installations were found in PATH or common locations"))
		return nil
	}

	active := ""
	for _, inst := range installs {
		if inst.Active {
			active = inst.DisplayPath
			break
		}
	}
	if active == "" {
		active = "not found in PATH"
	}
	fmt.Printf("  active:      %s\n", output.Highlight(active))

	for _, inst := range installs {
		label := "copy"
		if inst.Active {
			label = "active"
		}
		fmt.Printf("  %s:        %s\n", padDoctorLabel(label), output.Info(inst.DisplayPath))
		fmt.Printf("    version:  %s\n", fallbackDoctorValue(inst.Version))
		fmt.Printf("    source:   %s\n", fallbackDoctorValue(inst.ProbableSource))
		if inst.PackageManaged {
			fmt.Printf("    package:  %s\n", fallbackDoctorValue(inst.PackageName))
		}
		if inst.PackageManaged {
			fmt.Printf("    remove:   %s\n", output.Warning("managed by package manager; use sudo apt remove gomap"))
		} else if inst.RemovalSupported {
			fmt.Printf("    remove:   %s\n", output.Info("can be removed by gomap --remove"))
		} else {
			fmt.Printf("    remove:   %s\n", output.Warning("manual cleanup may be required"))
		}
	}

	if hasPATHShadowing(installs) {
		fmt.Printf("%s\n", output.StatusWarn("Multiple gomap binaries are present in PATH; older copies may shadow the packaged one"))
		fmt.Printf("%s\n", output.Info("Run `which -a gomap` and keep the intended installation first in PATH"))
	}

	return nil
}

func RemoveGomap() error {
	fmt.Println(output.Warning("⚠ Removing gomap from your system..."))
	fmt.Println("")

	installs, err := detectGomapInstallations()
	if err != nil {
		return err
	}
	if len(installs) == 0 {
		fmt.Println(output.Warning("⚠ Could not find gomap installation in PATH or common locations"))
		fmt.Println(output.Info("Try `gomap --doctor` or `which -a gomap` to inspect your environment"))
		return fmt.Errorf("gomap not found")
	}

	var removed []string
	var skipped []gomapInstallation

	for _, inst := range installs {
		if inst.PackageManaged {
			skipped = append(skipped, inst)
			continue
		}
		if !inst.RemovalSupported {
			continue
		}
		if tryRemoveFromPath(inst.Path) {
			removed = append(removed, inst.DisplayPath)
		}
	}

	for _, path := range removed {
		fmt.Printf("%s\n", output.StatusOK(fmt.Sprintf("Removed gomap from %s", output.Highlight(path))))
	}

	for _, inst := range skipped {
		fmt.Printf("%s\n", output.StatusWarn(fmt.Sprintf("Skipping %s because it is managed by %s", output.Highlight(inst.DisplayPath), output.Highlight(inst.PackageName))))
	}
	if len(skipped) > 0 {
		fmt.Printf("%s\n", output.Info("Use `sudo apt remove gomap` to remove the package-managed installation"))
	}

	if len(removed) == 0 {
		if len(skipped) > 0 {
			return fmt.Errorf("only package-managed installations found")
		}
		return fmt.Errorf("no removable gomap copies found")
	}
	return nil
}

func detectGomapInstallations() ([]gomapInstallation, error) {
	candidates := candidateBinaryPaths()
	activePath, _ := exec.LookPath("gomap")
	activeEval, _ := filepath.EvalSymlinks(activePath)

	seen := map[string]bool{}
	installs := make([]gomapInstallation, 0, len(candidates))

	for _, candidate := range candidates {
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			resolved = candidate
		}
		if seen[resolved] {
			continue
		}
		if _, err := os.Stat(resolved); err != nil {
			continue
		}
		seen[resolved] = true

		version, _ := readBinaryVersion(resolved)
		pkgName, pkgManaged := packageOwner(resolved)
		installs = append(installs, gomapInstallation{
			Path:             resolved,
			DisplayPath:      displayPath(resolved),
			Active:           resolved == activeEval || candidate == activePath,
			Exists:           true,
			Version:          version,
			PackageManaged:   pkgManaged,
			PackageName:      pkgName,
			ProbableSource:   probableInstallSource(resolved, pkgManaged, pkgName),
			RemovalSupported: !pkgManaged,
		})
	}

	return installs, nil
}

func candidateBinaryPaths() []string {
	paths := []string{}
	add := func(path string) {
		if strings.TrimSpace(path) == "" {
			return
		}
		paths = append(paths, path)
	}

	if pathEnv := os.Getenv("PATH"); pathEnv != "" {
		for _, dir := range filepath.SplitList(pathEnv) {
			add(filepath.Join(dir, "gomap"))
		}
	}

	add("/usr/local/bin/gomap")
	add("/usr/bin/gomap")

	if home, err := os.UserHomeDir(); err == nil {
		add(filepath.Join(home, ".local", "bin", "gomap"))
		add(filepath.Join(home, "bin", "gomap"))
		add(filepath.Join(home, "go", "bin", "gomap"))
	}

	if gobin, err := resolveGoInstalledBinaryPath(); err == nil {
		add(gobin)
	}

	return paths
}

func packageOwner(path string) (string, bool) {
	cmd := exec.Command("dpkg", "-S", path)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", false
	}
	line := strings.TrimSpace(stdout.String())
	if line == "" {
		return "", false
	}
	parts := strings.SplitN(line, ":", 2)
	if len(parts) == 0 {
		return "", false
	}
	name := strings.TrimSpace(parts[0])
	if name == "" {
		return "", false
	}
	return name, true
}

func probableInstallSource(path string, pkgManaged bool, pkgName string) string {
	if pkgManaged {
		return "package manager (" + pkgName + ")"
	}
	switch {
	case strings.Contains(path, string(filepath.Separator)+".local"+string(filepath.Separator)+"bin"+string(filepath.Separator)):
		return "user-local binary"
	case strings.Contains(path, string(filepath.Separator)+"go"+string(filepath.Separator)+"bin"+string(filepath.Separator)):
		return "go install"
	case strings.HasPrefix(path, "/usr/local/bin/"):
		return "manual system-wide install"
	case strings.HasPrefix(path, "/usr/bin/"):
		return "system binary"
	case strings.Contains(path, string(filepath.Separator)+"bin"+string(filepath.Separator)):
		return "user/system PATH binary"
	default:
		return "unknown"
	}
}

func displayPath(path string) string {
	if home, err := os.UserHomeDir(); err == nil {
		if path == home {
			return "~"
		}
		prefix := home + string(filepath.Separator)
		if strings.HasPrefix(path, prefix) {
			return "~/" + strings.TrimPrefix(path, prefix)
		}
	}
	return path
}

func hasPATHShadowing(installs []gomapInstallation) bool {
	count := 0
	for _, inst := range installs {
		if inst.Active || strings.Contains(inst.Path, string(filepath.Separator)+"bin"+string(filepath.Separator)) {
			count++
		}
	}
	return count > 1
}

func padDoctorLabel(label string) string {
	if len(label) >= 10 {
		return label
	}
	return label + strings.Repeat(" ", 10-len(label))
}

func fallbackDoctorValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return output.Warning("unknown")
	}
	return output.Info(value)
}

func tryRemoveFromPath(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}

	if err := os.Remove(path); err == nil {
		return true
	}

	if os.Geteuid() == 0 {
		return os.Remove(path) == nil
	}

	fmt.Println(output.Info("🔐 Requesting sudo to remove system-wide installation..."))

	cmd := exec.Command("sudo", "rm", "-f", path)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err == nil {
		return true
	}

	cmd = exec.Command("sudo", "-n", "rm", "-f", path)
	return cmd.Run() == nil
}
