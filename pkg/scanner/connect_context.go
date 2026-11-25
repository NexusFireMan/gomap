package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// ConnectOptions bounds the embeddable CONNECT engine, not CLI orchestration.
// Zero values select 32 workers, 100 starts/s and a 750 ms timeout. Optional
// native service detection has a four-second budget after CONNECT. A supplied
// limiter shares attempt starts across hosts, discovery and service sockets.
type ConnectOptions struct {
	Workers        int
	Rate           int
	Timeout        time.Duration
	DetectServices bool
	AttemptLimiter *AttemptLimiter
}

// ConnectSummary counts delivered observations only. Unreported ports were not
// classified, including work abandoned on cancellation or a consumer error.
type ConnectSummary struct {
	Requested  int   `json:"requested"`
	Completed  int   `json:"completed"`
	Open       int   `json:"open"`
	Closed     int   `json:"closed"`
	Filtered   int   `json:"filtered"`
	Unknown    int   `json:"unknown"`
	Unreported int   `json:"unreported"`
	Cancelled  bool  `json:"cancelled"`
	DurationMS int64 `json:"duration_ms"`
}

// ScanConnectContext defaults to connection-only probes without stdout, files,
// DNS or privileged operations. DetectServices opts into bounded native probes.
// The callback runs serially and
// must return promptly; return an error to stop. It must not modify ports.
// A timeout means inferred filtering, never a confirmed firewall drop.
func ScanConnectContext(ctx context.Context, host string, ports []int, opts ConnectOptions, onResult func(ScanResult) error) (ConnectSummary, error) {
	return scanConnectContext(ctx, host, ports, opts, onResult, nil)
}

func scanConnectContext(parent context.Context, host string, ports []int, opts ConnectOptions, onResult func(ScanResult) error, dial recoveryDialFunc) (ConnectSummary, error) {
	start := time.Now()
	ip, err := netip.ParseAddr(host)
	if err != nil || (!ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()) || ip.Zone() != "" {
		return ConnectSummary{}, errors.New("CONNECT requires one literal unicast IP without a zone")
	}
	if parent == nil || onResult == nil {
		return ConnectSummary{}, errors.New("context and result consumer are required")
	}
	if opts.Workers == 0 {
		opts.Workers = 32
	}
	if opts.Rate == 0 {
		opts.Rate = 100
	}
	if opts.Timeout == 0 {
		opts.Timeout = 750 * time.Millisecond
	}
	if opts.Workers < 1 || opts.Workers > 128 || opts.Rate < 1 || opts.Rate > 1000 || opts.Timeout < time.Millisecond || opts.Timeout > 10*time.Second {
		return ConnectSummary{}, errors.New("invalid CONNECT resource limits")
	}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return ConnectSummary{}, fmt.Errorf("invalid port: %d", port)
		}
	}
	ports = uniquePortsOrdered(ports)
	summary := ConnectSummary{Requested: len(ports), Unreported: len(ports)}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	s := NewScanner(ip.String(), false)
	s.Configure(ScanConfig{Timeout: opts.Timeout, AdaptiveTimeout: false})
	if dial == nil {
		dial = s.recoveryDial
	}
	limiter := opts.AttemptLimiter
	if limiter == nil {
		limiter = NewAttemptLimiter(opts.Rate)
	}
	workers := min(opts.Workers, len(ports))
	jobs := make(chan int)
	observations := make(chan ScanResult, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			worker := NewScanner(ip.String(), false)
			worker.Configure(ScanConfig{Timeout: opts.Timeout, AdaptiveTimeout: false})
			worker.AttemptLimiter = limiter
			worker.probeDial = dial
			for port := range jobs {
				if ctx.Err() != nil {
					return
				}
				var dialErr error
				probeCtx := ctx
				finish := func() {}
				worker.probeContext = probeCtx
				// Initial attempts are paced by this closure; additional service
				// sockets use the same limiter through the context-aware dialer.
				worker.AttemptLimiter = nil
				result := worker.scanPortWithDial(port, opts.DetectServices, func(address string, timeout time.Duration) (net.Conn, error) {
					if err := limiter.WaitContext(ctx); err != nil {
						dialErr = err
						return nil, err
					}
					conn, err := dial(ctx, address, timeout)
					dialErr = err
					if err != nil {
						return nil, err
					}
					if opts.DetectServices {
						probeCtx, finish = context.WithTimeout(ctx, 4*time.Second)
						worker.probeContext = probeCtx
						worker.AttemptLimiter = limiter
						// Keep the established connection for passive greetings.
					}
					conn, err = bindProbeConnection(probeCtx, conn)
					dialErr = err
					return conn, err
				})
				if result.IsOpen && opts.DetectServices && probeCtx.Err() != nil {
					result.Evidence += "; service budget exhausted"
				}
				finish()
				if ctx.Err() != nil {
					return
				}
				if result.IsOpen {
					result.State = "open"
					if result.Evidence == "" {
						result.Evidence = "TCP connection established"
					}
				} else {
					kind := dialErrorKind(dialErr)
					result.State = connectionIssueState(kind, false)
					result.Confidence = "low"
					result.Evidence = "TCP connection failed: " + kind
					if kind == "refused" {
						result.State = "closed"
						result.Evidence = "TCP connection refused"
					}
					if kind == "timeout" {
						result.Evidence = "TCP timeout; filtering inferred, not confirmed"
					}
				}
				select {
				case observations <- result:
				case <-ctx.Done():
					return
				}
			}
		})
	}
	wg.Go(func() {
		defer close(jobs)
		for _, port := range ports {
			if ctx.Err() != nil {
				return
			}
			select {
			case jobs <- port:
			case <-ctx.Done():
				return
			}
		}
	})
	go func() { wg.Wait(); close(observations) }()
	var consumerErr error
	for result := range observations {
		if ctx.Err() != nil {
			continue
		}
		if err := onResult(result); err != nil {
			consumerErr = err
			cancel()
			continue
		}
		summary.Completed++
		switch result.State {
		case "open":
			summary.Open++
		case "closed":
			summary.Closed++
		case "filtered":
			summary.Filtered++
		default:
			summary.Unknown++
		}
	}
	summary.Unreported = summary.Requested - summary.Completed
	summary.Cancelled = parent.Err() != nil
	summary.DurationMS = time.Since(start).Milliseconds()
	if consumerErr != nil {
		return summary, consumerErr
	}
	return summary, parent.Err()
}
