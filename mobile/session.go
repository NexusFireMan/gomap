// Package mobile exposes a small gomobile-compatible CONNECT bridge.
// It intentionally does not expose the CLI, filesystem or privileged operations.
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

// EventSchemaVersion identifies the experimental JSON event contract.
const EventSchemaVersion = 1

// Session owns one scan. Read NextEvent on a background thread until it returns
// an empty string, then read AwaitSummary for the final summary. Cancel when the
// owning lifecycle ends. Never block on Android's main thread.
type Session struct {
	cancel  context.CancelFunc
	events  chan string
	done    chan struct{}
	summary string
}

type event struct {
	SchemaVersion int                     `json:"schema_version"`
	Type          string                  `json:"type"`
	Host          string                  `json:"host"`
	Result        *scanner.ScanResult     `json:"result,omitempty"`
	Summary       *scanner.ConnectSummary `json:"summary,omitempty"`
	Error         string                  `json:"error,omitempty"`
	Discovery     *discoverySummary       `json:"discovery,omitempty"`
	HostResult    *hostObservation        `json:"host_result,omitempty"`
}

// StartConnect validates before starting work. The prototype accepts one literal
// IP and up to 4096 unique ports; it rejects larger scopes instead of truncating.
// Results use a bounded queue. A consumer must drain it or cancel the session.
func StartConnect(host, portSpec string) (*Session, error) {
	ip, err := netip.ParseAddr(host)
	if len(host) > 64 || err != nil || (!ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()) || ip.Zone() != "" {
		return nil, errors.New("enter one literal unicast IP without a zone")
	}
	if len(portSpec) > 8192 || strings.TrimSpace(portSpec) == "" {
		return nil, errors.New("an explicit port list of at most 8192 characters is required")
	}
	ports, err := parseSessionPorts(portSpec)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return startSession(ctx, cancel, ip.String(), ports, scanner.ScanConnectContext), nil
}

func parseSessionPorts(spec string) ([]int, error) {
	parts := strings.Split(spec, ",")
	if len(parts) > 256 {
		return nil, errors.New("prototype supports at most 256 port-list entries")
	}
	manager := scanner.NewPortManager()
	seen := make(map[int]bool)
	var ports []int
	for _, part := range parts {
		parsed, err := manager.ParsePorts(part)
		if err != nil {
			return nil, err
		}
		for _, port := range parsed {
			if seen[port] {
				continue
			}
			if len(ports) == 4096 {
				return nil, errors.New("prototype supports at most 4096 unique ports per session")
			}
			seen[port] = true
			ports = append(ports, port)
		}
	}
	return ports, nil
}

type connectRunner func(context.Context, string, []int, scanner.ConnectOptions, func(scanner.ScanResult) error) (scanner.ConnectSummary, error)

func startSession(ctx context.Context, cancel context.CancelFunc, host string, ports []int, run connectRunner) *Session {
	s := &Session{cancel: cancel, events: make(chan string, 32), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		defer close(s.events)
		defer cancel()
		summary, runErr := run(ctx, host, ports, scanner.ConnectOptions{}, func(result scanner.ScanResult) error {
			data, err := json.Marshal(event{SchemaVersion: EventSchemaVersion, Type: "result", Host: host, Result: &result})
			if err != nil {
				return err
			}
			select {
			case s.events <- string(data):
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		errorCode := ""
		if runErr != nil {
			errorCode = "scan_failed"
			if errors.Is(runErr, context.Canceled) {
				errorCode = "cancelled"
			}
		}
		data, err := json.Marshal(event{SchemaVersion: EventSchemaVersion, Type: "summary", Host: host, Summary: &summary, Error: errorCode})
		if err != nil {
			s.summary = `{"schema_version":1,"type":"error","error":"event_encoding_failed"}`
		} else {
			s.summary = string(data)
		}
	}()
	return s
}

// Cancel is concurrent-safe, idempotent and nonblocking, including from UI code.
// Queued results remain readable; unfinished ports remain unreported, not closed.
func (s *Session) Cancel() {
	if s != nil && s.cancel != nil {
		s.cancel()
	}
}

// NextEvent blocks for one JSON observation, or returns empty after queue closure.
// Use one background consumer; cancellation unblocks producers even if it stops.
func (s *Session) NextEvent() string {
	if s == nil || s.events == nil {
		return ""
	}
	return <-s.events
}

// AwaitSummary joins all scan workers and returns the final JSON summary. Drain NextEvent
// or Cancel first: a full result queue intentionally applies backpressure.
func (s *Session) AwaitSummary() string {
	if s == nil || s.done == nil {
		return `{"schema_version":1,"type":"error","error":"invalid_session"}`
	}
	<-s.done
	return s.summary
}
