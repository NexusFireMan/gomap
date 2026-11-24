package app

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/NexusFireMan/gomap/v2/pkg/output"
	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

// Mobile reports write completed sections directly, not a second report-sized
// buffer. Scan observations are still retained for coverage and structured output.
func writeMobileTextReport(w io.Writer, formatter *output.OutputFormatter, stream bool, targets []string, results map[string][]scanner.ScanResult, diagnostics map[string]scanner.ConnectDiagnostics, metrics output.ScanMetrics, duration time.Duration) (resultErr error) {
	buffer := bufio.NewWriter(w)
	defer func() {
		if err := buffer.Flush(); resultErr == nil {
			resultErr = err
		}
	}()
	w = buffer
	totalOpen := 0
	for _, host := range targets {
		totalOpen += scanner.CountOpen(results[host])
		if stream {
			continue
		}
		if len(targets) > 1 {
			if err := output.WriteMobileBlock(w, "Host: "+host); err != nil {
				return err
			}
		}
		if err := formatter.WriteResults(w, results[host]); err != nil {
			return err
		}
	}
	if err := writeMobileConnectWarnings(w, targets, diagnostics); err != nil {
		return err
	}
	for _, host := range targets {
		var diag *scanner.ConnectDiagnostics
		if d, ok := diagnostics[host]; ok {
			diag = &d
		}
		open, critical, exposure := hostExposure(results[host], diag)
		criticalText := "none"
		if len(critical) > 0 {
			criticalText = strings.Join(critical, ", ")
		}
		fields := [][2]string{{"host", host}, {"open ports", strconv.Itoa(open)}, {"critical", criticalText}, {"exposure", exposure}}
		if diag != nil {
			fields = append(fields, [2]string{"TCP closed (refused)", strconv.Itoa(diag.RefusedPorts)}, [2]string{"filtered (timeout-inferred)", strconv.Itoa(diag.FilteredPorts)}, [2]string{"unknown", strconv.Itoa(diag.UnresolvedPorts - diag.FilteredPorts)})
		}
		if err := output.WriteMobileBlock(w, "Host Exposure Summary", fields...); err != nil {
			return err
		}
	}
	if err := output.WriteScanMetrics(w, metrics); err != nil {
		return err
	}
	status := "Completed scan"
	if metrics.Coverage.Inconclusive() > 0 {
		status = "Scan finished (inconclusive)"
	}
	return output.WriteMobileBlock(w, status, [2]string{"duration", duration.Round(time.Millisecond).String()}, [2]string{"hosts", strconv.Itoa(len(targets))}, [2]string{"open ports", strconv.Itoa(totalOpen)}, [2]string{"inconclusive host-ports", strconv.Itoa(metrics.Coverage.Inconclusive())})
}

func writeMobileConnectWarnings(w io.Writer, targets []string, diagnostics map[string]scanner.ConnectDiagnostics) error {
	for _, host := range targets {
		diag := diagnostics[host]
		if diag.Recovery == nil && diag.UnresolvedPorts == 0 {
			continue
		}
		var fields [][2]string
		if r := diag.Recovery; r != nil {
			fields = append(fields, [2]string{"recovery attempts", strconv.Itoa(r.Attempts)}, [2]string{"recovery open", strconv.Itoa(r.Opened)}, [2]string{"recovery refused", strconv.Itoa(r.Refused)}, [2]string{"recovery elapsed ms", fmt.Sprint(r.ElapsedMS)}, [2]string{"recovery stop", r.Stop}, [2]string{"shared recovery budget", "8 attempts / 3000 ms"})
		}
		if diag.UnresolvedPorts > 0 {
			fields = append(fields, [2]string{"inconclusive TCP ports", strconv.Itoa(diag.UnresolvedPorts)}, [2]string{"state", "not confirmed closed"})
			counts, minTimeout, maxTimeout := connectionIssueDetails(diag)
			for _, count := range counts {
				fields = append(fields, [2]string{count.kind + "_ports", strconv.Itoa(count.count)})
			}
			fields = append(fields, [2]string{"closed (refused)", strconv.Itoa(diag.RefusedPorts)}, [2]string{"filtered (timeout-inferred)", strconv.Itoa(diag.FilteredPorts)}, [2]string{"unknown", strconv.Itoa(diag.UnresolvedPorts - diag.FilteredPorts)}, [2]string{"configured timeout ms", fmt.Sprint(diag.TimeoutMS)})
			if minTimeout > 0 {
				fields = append(fields, [2]string{"last attempt timeout ms", fmt.Sprintf("%d..%d", minTimeout, maxTimeout)})
			}
		}
		if err := output.WriteMobileBlock(w, "TCP diagnostics: "+host, fields...); err != nil {
			return err
		}
	}
	return nil
}

type issueCount struct {
	kind  string
	count int
}

func connectionIssueDetails(diag scanner.ConnectDiagnostics) ([]issueCount, int64, int64) {
	counts := make(map[string]int)
	var minTimeout, maxTimeout int64
	for _, issue := range diag.Issues {
		if issue.Recovered {
			continue
		}
		counts[issue.Kind]++
		if issue.TimeoutMS > 0 {
			if minTimeout == 0 || issue.TimeoutMS < minTimeout {
				minTimeout = issue.TimeoutMS
			}
			maxTimeout = max(maxTimeout, issue.TimeoutMS)
		}
	}
	var ordered []issueCount
	for kind, count := range counts {
		ordered = append(ordered, issueCount{kind, count})
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].kind < ordered[j].kind })
	return ordered, minTimeout, maxTimeout
}
