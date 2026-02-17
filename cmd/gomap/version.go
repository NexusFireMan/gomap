package gomap

var (
	// Version is injected at build time with -ldflags.
	Version = "2.1.1"
	// Commit is injected at build time with -ldflags.
	Commit = "dev"
	// Date is injected at build time with -ldflags.
	Date = "unknown"
	// RepoURL points to the project repository.
	RepoURL = "https://github.com/NexusFireMan/gomap"
	// ModulePath is the Go module import path used by go install.
	ModulePath = "github.com/NexusFireMan/gomap"
)
