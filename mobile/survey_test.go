package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

func TestSurveyScopeBounds(t *testing.T) {
	for _, target := range []string{"10.0.11.6", "10.0.11.7/24", "10.0.11.0/31", "10.0.11.0/32", "fd00::/120"} {
		p, err := planSurvey(target, "22,80,443", true, false)
		if err != nil || len(p.hosts) < 1 || len(p.hosts) > 256 {
			t.Fatal(target, p, err)
		}
	}
	for _, target := range []string{"10.0.11.6/32", "fd00::1/128"} {
		p, err := planSurvey(target, "22222", true, false)
		if err != nil || p.discover || len(p.hosts) != 1 {
			t.Fatal("single-host CIDR must bypass pre-discovery", p, err)
		}
		p, err = planSurvey(target, "", false, true)
		if err != nil || !p.discover {
			t.Fatal("explicit discovery mode was bypassed", p, err)
		}
	}
	for _, target := range []string{"fixture.invalid", "10.0.0.0/16", "fd00::/64", "ff02::/120", "0.0.0.0/24", "fe80::1%wlan0", "::ffff:10.0.11.0/120", "10.0.11.1,10.0.11.2", " 10.0.11.1"} {
		if _, err := planSurvey(target, "22", false, false); err == nil {
			t.Fatalf("accepted %q", target)
		}
	}
	if _, err := planSurvey("10.0.11.0/24", "1-17", false, false); err == nil {
		t.Fatal("accepted excessive host-port product")
	}
	p, err := planSurvey("10.0.11.7/24", "invalid ports ignored in discovery mode", true, true)
	if err != nil || len(p.hosts) != 254 || len(p.ports) != 0 || p.target != "10.0.11.0/24" {
		t.Fatal(p, err)
	}
}

func readSurvey(t *testing.T, s *Session) ([]event, event) {
	t.Helper()
	defer s.Cancel()
	var events []event
	for text := s.NextEvent(); text != ""; text = s.NextEvent() {
		var e event
		if err := json.Unmarshal([]byte(text), &e); err != nil || e.SchemaVersion != 2 {
			t.Fatal(text, err)
		}
		events = append(events, e)
	}
	var final event
	if err := json.Unmarshal([]byte(s.AwaitSummary()), &final); err != nil || final.SchemaVersion != 2 {
		t.Fatal(final, err)
	}
	return events, final
}

func TestSurveyHostIdentityCoverageAndRefusedDiscovery(t *testing.T) {
	plan, err := planSurvey("10.0.11.0/30", "22,80", true, false)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var limiters []*scanner.AttemptLimiter
	runner := func(ctx context.Context, host string, ports []int, opts scanner.ConnectOptions, emit func(scanner.ScanResult) error) (scanner.ConnectSummary, error) {
		mu.Lock()
		limiters = append(limiters, opts.AttemptLimiter)
		mu.Unlock()
		if opts.Timeout != 0 {
			if host == "10.0.11.1" {
				return scanner.ConnectSummary{}, emit(scanner.ScanResult{Port: 443, State: "closed", Evidence: "TCP connection refused"})
			}
			return scanner.ConnectSummary{}, nil
		}
		if !opts.DetectServices {
			t.Error("service option lost")
		}
		summary := scanner.ConnectSummary{Requested: len(ports)}
		for _, port := range ports {
			if err := emit(scanner.ScanResult{Port: port, State: "open", IsOpen: true, ServiceName: "ssh", Version: "OpenSSH 9.9", Confidence: "high", Evidence: "SSH-2.0-OpenSSH_9.9\x1b\u202e"}); err != nil {
				return summary, err
			}
			summary.Completed++
			summary.Open++
		}
		return summary, ctx.Err()
	}
	events, final := readSurvey(t, startSurvey(plan, runner))
	if final.Error != "" || final.Discovery == nil || final.Discovery.Responding != 1 || final.Discovery.NoResponse != 1 || final.Summary.Requested != 4 || final.Summary.Open != 2 || final.Summary.Unreported != 2 {
		t.Fatalf("invalid summary: %+v", final)
	}
	results := 0
	for _, e := range events {
		if e.Result == nil {
			continue
		}
		results++
		if e.Host != "10.0.11.1" || strings.ContainsAny(e.Result.Evidence, "\x1b\u202e") {
			t.Fatal(e)
		}
	}
	if results != 2 {
		t.Fatal(results)
	}
	for _, limiter := range limiters {
		if limiter == nil || limiter != limiters[0] {
			t.Fatal("attempt budget was not shared across phases")
		}
	}
}

func TestSurveyDiscoveryOnlyAndSamePortAcrossHosts(t *testing.T) {
	for _, only := range []bool{true, false} {
		plan, _ := planSurvey("10.0.11.0/30", "443", true, only)
		runner := func(_ context.Context, _ string, _ []int, opts scanner.ConnectOptions, emit func(scanner.ScanResult) error) (scanner.ConnectSummary, error) {
			err := emit(scanner.ScanResult{Port: 443, State: "open", IsOpen: true, Evidence: "TCP connection established"})
			if opts.Timeout != 0 {
				return scanner.ConnectSummary{}, err
			}
			return scanner.ConnectSummary{Requested: 1, Completed: 1, Open: 1}, err
		}
		events, final := readSurvey(t, startSurvey(plan, runner))
		if final.Error != "" || final.Discovery.Responding != 2 || final.Discovery.Unreported != 0 {
			t.Fatal(final)
		}
		results := map[string]bool{}
		for _, e := range events {
			if e.Result != nil {
				results[e.Host] = true
			}
		}
		if only {
			if len(results) != 0 || final.Summary.Requested != 0 {
				t.Fatal("discovery scanned requested ports")
			}
		} else if len(results) != 2 || final.Summary.Completed != 2 {
			t.Fatal("host identities collided")
		}
	}
}

func TestSurveyCancelDiscoveryJoinsAndPreservesUnreported(t *testing.T) {
	plan, _ := planSurvey("10.0.11.0/24", "22", false, false)
	entered := make(chan struct{}, 16)
	runner := func(ctx context.Context, _ string, _ []int, _ scanner.ConnectOptions, _ func(scanner.ScanResult) error) (scanner.ConnectSummary, error) {
		entered <- struct{}{}
		<-ctx.Done()
		return scanner.ConnectSummary{}, ctx.Err()
	}
	s := startSurvey(plan, runner)
	for range 16 {
		<-entered
	}
	s.Cancel()
	_, final := readSurvey(t, s)
	if final.Error != "cancelled" || !final.Summary.Cancelled || final.Summary.Completed != 0 || final.Summary.Unreported != 254 || final.Discovery.Unreported != 254 {
		t.Fatal(final)
	}
}

func TestSurveyFailureAndBoundedEvidence(t *testing.T) {
	plan, _ := planSurvey("10.0.11.1", "443", true, false)
	_, final := readSurvey(t, startSurvey(plan, func(context.Context, string, []int, scanner.ConnectOptions, func(scanner.ScanResult) error) (scanner.ConnectSummary, error) {
		return scanner.ConnectSummary{}, errors.New("fixture failed")
	}))
	if final.Error != "scan_failed" || final.Summary.Unreported != 1 {
		t.Fatal(final)
	}
	if got := boundedText(strings.Repeat("a", 3000)+"\x00\u202e", 2048); len(got) != 2048 {
		t.Fatal(len(got))
	}
}
