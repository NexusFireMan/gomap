package gomap

import (
	"regexp"
	"runtime/debug"
	"strings"
	"time"
)

var (
	// Version is injected at build time with -ldflags.
	Version = "2.3.1"
	// Commit is injected at build time with -ldflags.
	Commit = "dev"
	// Date is injected at build time with -ldflags.
	Date = "unknown"
	// RepoURL points to the project repository.
	RepoURL = "https://github.com/NexusFireMan/gomap"
	// ModulePath is the Go module import path used by go install.
	ModulePath = "github.com/NexusFireMan/gomap/v2"
)

// EffectiveBuildInfo returns user-facing version metadata, with runtime fallbacks
// when ldflags are not embedded (for example plain go install builds).
func EffectiveBuildInfo() (version, commit, date string) {
	version = Version
	commit = Commit
	date = Date

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return normalizeMetadata(version, commit, date)
	}

	if version == "" && info.Main.Version != "" {
		version = info.Main.Version
	}

	var vcsRevision, vcsTime string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			vcsRevision = strings.TrimSpace(s.Value)
		case "vcs.time":
			vcsTime = strings.TrimSpace(s.Value)
		}
	}

	if (commit == "" || commit == "dev") && vcsRevision != "" {
		commit = shortCommit(vcsRevision)
	}
	if (date == "" || date == "unknown") && vcsTime != "" {
		date = vcsTime
	}

	// Fallback for pseudo versions (v0.0.0-YYYYMMDDHHMMSS-abcdef123456).
	if (commit == "" || commit == "dev" || commit == "n/a") || (date == "" || date == "unknown" || date == "n/a") {
		if pvDate, pvCommit := parsePseudoVersion(info.Main.Version); pvDate != "" || pvCommit != "" {
			if (date == "" || date == "unknown" || date == "n/a") && pvDate != "" {
				date = pvDate
			}
			if (commit == "" || commit == "dev" || commit == "n/a") && pvCommit != "" {
				commit = pvCommit
			}
		}
	}

	return normalizeMetadata(version, commit, date)
}

func normalizeMetadata(version, commit, date string) (string, string, string) {
	if strings.TrimSpace(version) == "" {
		version = "dev"
	}
	if strings.TrimSpace(commit) == "" || commit == "dev" {
		commit = "n/a"
	}
	if strings.TrimSpace(date) == "" || date == "unknown" {
		date = "n/a"
	}
	return version, commit, date
}

func shortCommit(commit string) string {
	commit = strings.TrimSpace(commit)
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}

var pseudoVersionRe = regexp.MustCompile(`^v\d+\.\d+\.\d+-([0-9]{14})-([0-9a-f]{12,})$`)

func parsePseudoVersion(v string) (date, commit string) {
	m := pseudoVersionRe.FindStringSubmatch(strings.TrimSpace(v))
	if len(m) != 3 {
		return "", ""
	}

	ts := m[1]
	t, err := time.Parse("20060102150405", ts)
	if err == nil {
		date = t.UTC().Format(time.RFC3339)
	}
	commit = shortCommit(m[2])
	return date, commit
}
