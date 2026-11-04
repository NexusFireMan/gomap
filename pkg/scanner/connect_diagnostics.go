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
	State     string `json:"state,omitempty"`
	TimeoutMS int64  `json:"timeout_ms,omitempty"`
}

type ConnectDiagnostics struct {
	Recovery       *TimeoutRecoveryDiagnostics `json:"timeout_recovery,omitempty"`
	AttemptedPorts int                         `json:"attempted_ports"`
	RefusedPorts   int                         `json:"refused_ports"`
	// UnresolvedPorts includes FilteredPorts for compatibility and completeness checks.
	UnresolvedPorts int               `json:"unresolved_ports"`
	RecoveredPorts  int               `json:"recovered_ports"`
	FilteredPorts   int               `json:"filtered_ports"`
	TimeoutMS       int64             `json:"configured_timeout_ms"`
	Issues          []ConnectionIssue `json:"issues,omitempty"`
}

// A timeout is consistent with filtering, but cannot prove a firewall dropped a packet.
func connectionIssueState(kind string, recovered bool) string {
	if recovered {
		return "open"
	}
	if kind == "timeout" {
		return "filtered"
	}
	return "unknown"
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
