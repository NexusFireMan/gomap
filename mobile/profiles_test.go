package mobile

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

func TestSurveyBudgetAfterDiscovery(t *testing.T) {
	for _, responding := range []int{0, 5, 65, 66} {
		t.Run(fmt.Sprint(responding), func(t *testing.T) {
			plan, err := planSurvey("10.0.11.0/24", "@common1000", false, false)
			if err != nil {
				t.Fatal(err)
			}
			active := make(map[string]bool)
			for _, host := range plan.hosts[:responding] {
				active[host] = true
			}
			var discoveries, scans atomic.Int32
			_, final := readSurvey(t, startSurvey(plan, func(_ context.Context, host string, ports []int, opts scanner.ConnectOptions, emit func(scanner.ScanResult) error) (scanner.ConnectSummary, error) {
				if opts.Timeout != 0 {
					discoveries.Add(1)
					if active[host] {
						return scanner.ConnectSummary{}, emit(scanner.ScanResult{Port: 443, State: "closed"})
					}
					return scanner.ConnectSummary{}, nil
				}
				if discoveries.Load() != 254 || !active[host] {
					t.Error("scan started before discovery finished or on a silent host")
				}
				scans.Add(1)
				summary := scanner.ConnectSummary{Requested: len(ports)}
				for _, port := range ports {
					if err := emit(scanner.ScanResult{Port: port, State: "closed"}); err != nil {
						return summary, err
					}
					summary.Completed++
					summary.Closed++
				}
				return summary, nil
			}))
			wantScans, wantError := responding, ""
			if responding > 65 {
				wantScans, wantError = 0, "scope_limit"
			}
			if int(scans.Load()) != wantScans || final.Error != wantError || final.Discovery.Responding != responding || final.Summary.Requested != 254000 || final.Summary.Completed != wantScans*1000 || final.Summary.Unreported != 254000-wantScans*1000 {
				t.Fatalf("scans=%d summary=%+v discovery=%+v error=%s", scans.Load(), final.Summary, final.Discovery, final.Error)
			}
		})
	}
}

func TestSurveyPortProfiles(t *testing.T) {
	common, err := surveyPorts("@common1000")
	if err != nil || len(common) != 1000 {
		t.Fatal(len(common), err)
	}
	seen := make(map[int]bool)
	for _, port := range common {
		if port < 1 || port > 65535 || seen[port] {
			t.Fatal("invalid common profile", port)
		}
		seen[port] = true
	}
	for _, port := range append(scanner.GetTop1000Ports(), 1883, 5672, 6379, 11211) {
		if !seen[port] {
			t.Fatal("missing curated port", port)
		}
	}
	for _, spec := range []string{"1-65535", "-"} {
		p, err := planSurvey("10.0.11.1", spec, false, false)
		if err != nil || len(p.ports) != 65535 || p.ports[0] != 1 || p.ports[65534] != 65535 {
			t.Fatal(spec, len(p.ports), err)
		}
	}
	if _, err := planSurvey("10.0.11.0/24", "@common1000", false, false); err != nil {
		t.Fatal("CIDR rejected before discovery", err)
	}
	if _, err := planSurvey("10.0.11.0/26", "@common1000", false, false); err != nil {
		t.Fatal("bounded common CIDR rejected", err)
	}
	if _, err := parseSessionPorts("1-4097"); err == nil {
		t.Fatal("legacy bridge limits changed")
	}
}

func TestSurveyFullRangeWithoutNetworkOrDroppedRows(t *testing.T) {
	plan, _ := planSurvey("10.0.11.1", "1-65535", false, false)
	s := startSurvey(plan, func(_ context.Context, _ string, ports []int, opts scanner.ConnectOptions, emit func(scanner.ScanResult) error) (scanner.ConnectSummary, error) {
		if opts.Workers != 32 {
			t.Error("single-host worker budget regressed", opts.Workers)
		}
		summary := scanner.ConnectSummary{Requested: len(ports)}
		for _, port := range ports {
			if err := emit(scanner.ScanResult{Port: port, State: "closed", Evidence: "TCP connection refused"}); err != nil {
				return summary, err
			}
			summary.Completed++
			summary.Closed++
		}
		return summary, nil
	})
	defer s.Cancel()
	seen := make([]bool, 65536)
	count := 0
	for text := s.NextEvent(); text != ""; text = s.NextEvent() {
		var e event
		if err := json.Unmarshal([]byte(text), &e); err != nil || e.Result == nil || e.Result.Port < 1 || e.Result.Port > 65535 {
			t.Fatal(text, err)
		}
		if seen[e.Result.Port] {
			t.Fatal("duplicate port", e.Result.Port)
		}
		seen[e.Result.Port] = true
		count++
	}
	var final event
	if err := json.Unmarshal([]byte(s.AwaitSummary()), &final); err != nil {
		t.Fatal(err)
	}
	if count != 65535 || final.Summary.Completed != count || final.Summary.Closed != count || final.Summary.Unreported != 0 || final.Error != "" {
		t.Fatal(count, final)
	}
}

func TestSurveyOpenResultGuardStopsWithExplicitPartialCoverage(t *testing.T) {
	plan, _ := planSurvey("10.0.11.1", "1-15001", false, false)
	_, final := readSurvey(t, startSurvey(plan, func(_ context.Context, _ string, ports []int, _ scanner.ConnectOptions, emit func(scanner.ScanResult) error) (scanner.ConnectSummary, error) {
		summary := scanner.ConnectSummary{Requested: len(ports)}
		for _, port := range ports {
			if err := emit(scanner.ScanResult{Port: port, State: "open", IsOpen: true}); err != nil {
				return summary, err
			}
			summary.Completed++
			summary.Open++
		}
		return summary, nil
	}))
	if final.Error != "result_limit" || final.Summary.Completed != 10000 || final.Summary.Open != 10000 || final.Summary.Unreported != 5001 {
		t.Fatal(final)
	}
}
