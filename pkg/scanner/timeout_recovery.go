package scanner

import (
	"context"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"
)

// TimeoutRecoveryBudget must be shared across hosts to bound extra work per run.
// It is independent of the existing retry count and never replenishes itself.
type TimeoutRecoveryBudget struct {
	mu        sync.Mutex
	attempts  int
	remaining time.Duration
}

func NewTimeoutRecoveryBudget() *TimeoutRecoveryBudget {
	return &TimeoutRecoveryBudget{attempts: 8, remaining: 3 * time.Second}
}

type TimeoutRecoveryObservation struct {
	Before    ConnectionIssue `json:"before"`
	Kind      string          `json:"kind"`
	Error     string          `json:"error,omitempty"`
	TimeoutMS int64           `json:"timeout_ms"`
}

type TimeoutRecoveryDiagnostics struct {
	InitialOpen       int                          `json:"initial_open"`
	InitialRefused    int                          `json:"initial_refused"`
	InitialUnresolved int                          `json:"initial_unresolved"`
	InitialFiltered   int                          `json:"initial_filtered"`
	Attempts          int                          `json:"attempts"`
	Opened            int                          `json:"opened"`
	Refused           int                          `json:"refused"`
	ElapsedMS         int64                        `json:"elapsed_ms"`
	Stop              string                       `json:"stop"`
	Observations      []TimeoutRecoveryObservation `json:"observations,omitempty"`
}

type recoveryDialFunc func(context.Context, string, time.Duration) (net.Conn, error)

func (s *Scanner) recoveryDial(ctx context.Context, address string, timeout time.Duration) (net.Conn, error) {
	return s.dialerFor("tcp", address, timeout).DialContext(ctx, "tcp", address)
}

func (s *Scanner) recoverTimeouts(parent context.Context, results []ScanResult, diag ConnectDiagnostics, detectServices bool, dial recoveryDialFunc) ([]ScanResult, ConnectDiagnostics) {
	if s.RecoveryBudget == nil || diag.Recovery != nil {
		return results, diag
	}
	r := &TimeoutRecoveryDiagnostics{InitialOpen: len(results), InitialRefused: diag.RefusedPorts, InitialUnresolved: diag.UnresolvedPorts, InitialFiltered: diag.FilteredPorts}
	diag.Recovery = r
	if s.GhostMode {
		r.Stop = "controlled_profile"
		return results, diag
	}
	if diag.FilteredPorts > 32 {
		r.Stop = "broad_silence"
		return results, diag
	}
	open := make(map[int]bool)
	for _, result := range results {
		open[result.Port] = true
	}
	indices := make(map[int]int)
	var ports []int
	for i, issue := range diag.Issues {
		if issue.Kind != "timeout" || issue.Recovered {
			continue
		}
		_, duplicate := indices[issue.Port]
		if issue.Port < 1 || issue.Port > 65535 || duplicate || open[issue.Port] {
			r.Stop = "invalid_diagnostics"
			return results, diag
		}
		indices[issue.Port] = i
		ports = append(ports, issue.Port)
		if len(ports) > 32 {
			r.Stop = "broad_silence"
			return results, diag
		}
	}
	if len(ports) != diag.FilteredPorts || diag.UnresolvedPorts < diag.FilteredPorts {
		r.Stop = "invalid_diagnostics"
		return results, diag
	}
	if len(ports) == 0 {
		r.Stop = "no_timeouts"
		return results, diag
	}
	b := s.RecoveryBudget
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.attempts <= 0 {
		r.Stop = "attempt_budget"
		return results, diag
	}
	if b.remaining <= 0 {
		r.Stop = "time_budget"
		return results, diag
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(parent, b.remaining)
	defer cancel()
	defer func() {
		elapsed := time.Since(start)
		b.remaining = max(0, b.remaining-elapsed)
		r.ElapsedMS = elapsed.Milliseconds()
	}()
	rate := 10
	if s.Rate > 0 {
		rate = min(rate, s.Rate)
	}
	pacer := NewAttemptLimiter(rate)
	s.adaptiveMu.Lock()
	pacer.next = s.lastConnectStart.Add(pacer.interval)
	s.adaptiveMu.Unlock()
	slices.Sort(ports)
	results = slices.Clone(results)
	diag.Issues = slices.Clone(diag.Issues)
	removed := make(map[int]bool)
	r.Stop = "completed"
	for _, port := range ports {
		if b.attempts == 0 {
			r.Stop = "attempt_budget"
			break
		}
		if err := pacer.WaitContext(ctx); err != nil {
			r.Stop = recoveryContextStop(parent)
			break
		}
		if err := s.AttemptLimiter.WaitContext(ctx); err != nil {
			r.Stop = recoveryContextStop(parent)
			break
		}
		if ctx.Err() != nil {
			r.Stop = recoveryContextStop(parent)
			break
		}
		attemptStart := time.Now()
		pacer.next = attemptStart.Add(pacer.interval)
		s.adaptiveMu.Lock()
		s.lastConnectStart = attemptStart
		s.adaptiveMu.Unlock()
		deadline, _ := ctx.Deadline()
		timeout := min(1500*time.Millisecond, time.Until(deadline))
		if timeout < time.Millisecond {
			r.Stop = recoveryContextStop(parent)
			break
		}
		b.attempts--
		r.Attempts++
		conn, err := dial(ctx, net.JoinHostPort(s.Host, strconv.Itoa(port)), timeout)
		connected := conn != nil && err == nil
		if conn != nil {
			_ = conn.Close()
		}
		index := indices[port]
		before := diag.Issues[index]
		kind := dialErrorKind(err)
		if connected {
			kind = "open"
		}
		observation := TimeoutRecoveryObservation{Before: before, Kind: kind, TimeoutMS: timeout.Milliseconds()}
		if err != nil {
			observation.Error = err.Error()
		}
		r.Observations = append(r.Observations, observation)
		updated := before
		updated.Attempts++
		switch kind {
		case "open":
			diag.UnresolvedPorts--
			diag.FilteredPorts--
			diag.RecoveredPorts++
			r.Opened++
			updated.Recovered, updated.State = true, "open"
			latency := time.Since(attemptStart)
			result := ScanResult{Port: port, IsOpen: true, Confidence: "low", DetectionPath: "timeout-recovery", Evidence: "TCP connection established after timeout; service not fingerprinted", Latency: latency, LatencyMs: max(1, latency.Milliseconds())}
			result.ServiceName = s.PortManager.GetServiceName(port, "")
			if result.ServiceName == "" {
				result.ServiceName = "unknown"
			}
			if detectServices {
				result.Version = "TCP service (recovered; not fingerprinted)"
			}
			results = append(results, result)
			if s.OnResult != nil {
				s.OnResult(result)
			}
		case "refused":
			diag.UnresolvedPorts--
			diag.FilteredPorts--
			diag.RefusedPorts++
			r.Refused++
			removed[port] = true
		default:
			if kind != "timeout" {
				updated.State = "unknown"
				diag.FilteredPorts--
			}
			updated.Kind, updated.Error, updated.TimeoutMS = kind, observation.Error, observation.TimeoutMS
		}
		diag.Issues[index] = updated
	}
	if len(removed) > 0 {
		kept := make([]ConnectionIssue, 0, len(diag.Issues)-len(removed))
		for _, issue := range diag.Issues {
			if !removed[issue.Port] {
				kept = append(kept, issue)
			}
		}
		diag.Issues = kept
	}
	slices.SortFunc(results, func(a, b ScanResult) int { return a.Port - b.Port })
	return results, diag
}

func recoveryContextStop(parent context.Context) string {
	if parent.Err() != nil {
		return "canceled"
	}
	return "time_budget"
}
