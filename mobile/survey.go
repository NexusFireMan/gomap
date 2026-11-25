package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

const surveySchema = 2
const maxSurveyPairs = 65535
const maxSurveyOpenResults = 10000

var errSurveyResultLimit = errors.New("mobile open-result limit reached")
var errSurveyScopeLimit = errors.New("responding hosts exceed the mobile host-port limit")

func surveyPorts(spec string) ([]int, error) {
	if spec == "@common1000" {
		ports := scanner.GetTop1000Ports()
		seen := make(map[int]bool, len(ports))
		for _, port := range ports {
			seen[port] = true
		}
		// Keep the CLI list unchanged; include four common application protocols
		// absent from its current 996-entry curated TCP profile.
		for _, port := range []int{1883, 5672, 6379, 11211} {
			if !seen[port] {
				ports = append(ports, port)
				seen[port] = true
			}
		}
		if len(ports) != 1000 {
			return nil, errors.New("common port profile changed; review its membership")
		}
		return ports, nil
	}
	return parseBoundedPorts(spec, 65535)
}

// hostObservation is TCP reachability evidence, not an assertion that silence
// means a host is down. A refusal also establishes a responding endpoint.
type hostObservation struct {
	Address  string `json:"address"`
	State    string `json:"state"`
	Evidence string `json:"evidence"`
}

// discoverySummary accounts for delivered host observations, including silence.
type discoverySummary struct {
	Requested  int `json:"requested"`
	Completed  int `json:"completed"`
	Responding int `json:"responding"`
	NoResponse int `json:"no_response"`
	Unknown    int `json:"unknown"`
	Unreported int `json:"unreported"`
}

type surveyPlan struct {
	target       string
	hosts        []string
	ports        []int
	discover     bool
	discoverOnly bool
	services     bool
}

func planSurvey(target, portSpec string, services, discoverOnly bool) (surveyPlan, error) {
	plan := surveyPlan{target: target, services: services, discoverOnly: discoverOnly, discover: discoverOnly}
	if len(target) > 80 || strings.TrimSpace(target) != target {
		return plan, errors.New("enter one literal IP or a CIDR with at most 256 addresses")
	}
	if strings.Contains(target, "/") {
		prefix, err := netip.ParsePrefix(target)
		if err != nil || prefix.Addr().Is4In6() || prefix.Addr().IsUnspecified() || prefix.Bits() < prefix.Addr().BitLen()-8 {
			return plan, errors.New("CIDR supports at most 256 addresses (IPv4 /24 or smaller; IPv6 /120 or smaller)")
		}
		plan.target = prefix.Masked().String()
		plan.hosts, err = scanner.ExpandCIDR(plan.target)
		if err != nil {
			return plan, err
		}
		plan.discover = discoverOnly || len(plan.hosts) > 1
	} else {
		ip, err := netip.ParseAddr(target)
		if err != nil {
			return plan, errors.New("enter a literal IP or CIDR, not a hostname")
		}
		plan.hosts = []string{ip.Unmap().String()}
		plan.target = plan.hosts[0]
	}
	for _, host := range plan.hosts {
		ip, err := netip.ParseAddr(host)
		if err != nil || ip.Zone() != "" || (!ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()) {
			return plan, errors.New("scope must contain only unicast IPs without zones")
		}
	}
	if discoverOnly {
		return plan, nil
	}
	if len(portSpec) > 8192 || strings.TrimSpace(portSpec) == "" {
		return plan, errors.New("an explicit port list of at most 8192 characters is required")
	}
	var err error
	if portSpec == "-" {
		portSpec = "1-65535"
	}
	plan.ports, err = surveyPorts(portSpec)
	if err != nil {
		return plan, err
	}
	return plan, nil
}

// StartSurvey supports bounded TCP host discovery and optional native service
// detection. Schema 2 retains host identity on every observation; StartConnect
// remains available with its original schema and connection-only behavior.
func StartSurvey(target, ports string, services, discoverOnly bool) (*Session, error) {
	plan, err := planSurvey(target, ports, services, discoverOnly)
	if err != nil {
		return nil, err
	}
	return startSurvey(plan, scanner.ScanConnectContext), nil
}

func (s *Session) emit(ctx context.Context, value event) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	select {
	case s.events <- string(data):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

var errHostResponded = errors.New("TCP endpoint responded")

func startSurvey(plan surveyPlan, run connectRunner) *Session {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{cancel: cancel, events: make(chan string, 32), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		defer close(s.events)
		defer cancel()
		started := time.Now()
		limiter := scanner.NewAttemptLimiter(100)
		var discovery *discoverySummary
		var runErr error
		active := plan.hosts
		if plan.discover {
			outcomes := make([]hostObservation, len(plan.hosts))
			runErr = surveyHosts(ctx, plan.hosts, 16, func(ctx context.Context, index int, host string) error {
				observation := hostObservation{Address: host, State: "no_response", Evidence: "No TCP response on discovery ports 443,80,22,445,3389; not confirmed down"}
				_, err := run(ctx, host, []int{443, 80, 22, 445, 3389}, scanner.ConnectOptions{Workers: 1, Timeout: 400 * time.Millisecond, AttemptLimiter: limiter}, func(result scanner.ScanResult) error {
					if result.State == "open" || result.State == "closed" {
						observation.State = "responding"
						observation.Evidence = fmt.Sprintf("tcp/%d: %s", result.Port, result.Evidence)
						return errHostResponded
					}
					if result.State == "unknown" {
						observation.State = "unknown"
						observation.Evidence = "TCP discovery failed; reachability unknown"
					}
					return nil
				})
				if err != nil && !errors.Is(err, errHostResponded) {
					return err
				}
				if err := s.emit(ctx, event{SchemaVersion: surveySchema, Type: "host", Host: host, HostResult: &observation}); err != nil {
					return err
				}
				outcomes[index] = observation
				return nil
			})
			discovery = &discoverySummary{Requested: len(plan.hosts)}
			active = nil
			for _, observation := range outcomes {
				if observation.State == "" {
					continue
				}
				discovery.Completed++
				switch observation.State {
				case "responding":
					discovery.Responding++
					active = append(active, observation.Address)
				case "no_response":
					discovery.NoResponse++
				default:
					discovery.Unknown++
				}
			}
			discovery.Unreported = discovery.Requested - discovery.Completed
		}
		coverage := scanner.ConnectSummary{Requested: len(plan.hosts) * len(plan.ports)}
		if runErr == nil && !plan.discoverOnly && len(active)*len(plan.ports) > maxSurveyPairs {
			runErr = errSurveyScopeLimit
		}
		if runErr == nil && !plan.discoverOnly {
			var openMu sync.Mutex
			openResults := 0
			hostWorkers := min(4, len(active))
			portWorkers := 32 / max(1, hostWorkers)
			summaries := make([]scanner.ConnectSummary, len(active))
			runErr = surveyHosts(ctx, active, hostWorkers, func(ctx context.Context, index int, host string) error {
				summary, err := run(ctx, host, plan.ports, scanner.ConnectOptions{Workers: portWorkers, DetectServices: plan.services, AttemptLimiter: limiter}, func(result scanner.ScanResult) error {
					if result.IsOpen {
						openMu.Lock()
						if openResults == maxSurveyOpenResults {
							openMu.Unlock()
							return errSurveyResultLimit
						}
						openResults++
						openMu.Unlock()
					}
					result.ServiceName = boundedText(result.ServiceName, 128)
					result.Version = boundedText(result.Version, 512)
					result.Hostname = boundedText(result.Hostname, 256)
					result.Evidence = boundedText(result.Evidence, 2048)
					return s.emit(ctx, event{SchemaVersion: surveySchema, Type: "result", Host: host, Result: &result})
				})
				summaries[index] = summary
				return err
			})
			for _, summary := range summaries {
				coverage.Completed += summary.Completed
				coverage.Open += summary.Open
				coverage.Closed += summary.Closed
				coverage.Filtered += summary.Filtered
				coverage.Unknown += summary.Unknown
			}
		}
		coverage.Unreported = coverage.Requested - coverage.Completed
		coverage.Cancelled = ctx.Err() != nil
		coverage.DurationMS = time.Since(started).Milliseconds()
		code := ""
		if runErr != nil {
			code = "scan_failed"
			if errors.Is(runErr, errSurveyResultLimit) {
				code = "result_limit"
			}
			if errors.Is(runErr, errSurveyScopeLimit) {
				code = "scope_limit"
			}
			if errors.Is(runErr, context.Canceled) {
				code = "cancelled"
			}
		}
		data, err := json.Marshal(event{SchemaVersion: surveySchema, Type: "summary", Host: plan.target, Summary: &coverage, Discovery: discovery, Error: code})
		if err != nil {
			s.summary = `{"schema_version":2,"type":"error","error":"event_encoding_failed"}`
		} else {
			s.summary = string(data)
		}
	}()
	return s
}

// All work joins before returning. Distinct output slots are read after the join.
func surveyHosts(parent context.Context, hosts []string, workers int, work func(context.Context, int, string) error) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	jobs := make(chan int)
	var wg sync.WaitGroup
	var once sync.Once
	var firstErr error
	for range min(workers, len(hosts)) {
		wg.Go(func() {
			for index := range jobs {
				if ctx.Err() != nil {
					return
				}
				if err := work(ctx, index, hosts[index]); err != nil {
					once.Do(func() { firstErr = err; cancel() })
					return
				}
			}
		})
	}
dispatch:
	for index := range hosts {
		select {
		case jobs <- index:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	return parent.Err()
}

func boundedText(text string, limit int) string {
	var out strings.Builder
	for _, r := range text {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if out.Len()+len(string(r)) > limit {
			break
		}
		out.WriteRune(r)
	}
	return out.String()
}
