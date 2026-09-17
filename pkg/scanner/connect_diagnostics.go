package scanner

import (
	"errors"
	"syscall"
)

// ConnectionIssue records the last failed dial for an unresolved or recovered port.
type ConnectionIssue struct {
	Port      int    `json:"port"`
	Attempts  int    `json:"attempts"`
	Kind      string `json:"kind"`
	Error     string `json:"error"`
	Recovered bool   `json:"recovered,omitempty"`
}

type ConnectDiagnostics struct {
	AttemptedPorts  int               `json:"attempted_ports"`
	RefusedPorts    int               `json:"refused_ports"`
	UnresolvedPorts int               `json:"unresolved_ports"`
	RecoveredPorts  int               `json:"recovered_ports"`
	Issues          []ConnectionIssue `json:"issues,omitempty"`
}

func dialErrorKind(err error) string {
	if isDialTimeoutError(err) {
		return "timeout"
	}
	for _, entry := range []struct {
		kind string
		errs []error
	}{
		{"refused", []error{syscall.ECONNREFUSED}},
		{"unreachable", []error{syscall.EHOSTUNREACH, syscall.ENETUNREACH}},
		{"reset", []error{syscall.ECONNRESET, syscall.ECONNABORTED}},
		{"local_resource", []error{syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.EAGAIN, syscall.EADDRNOTAVAIL}},
		{"permission", []error{syscall.EPERM, syscall.EACCES}},
	} {
		for _, cause := range entry.errs {
			if errors.Is(err, cause) {
				return entry.kind
			}
		}
	}
	return "other"
}
