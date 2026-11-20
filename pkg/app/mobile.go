package app

import (
	"time"

	"github.com/NexusFireMan/gomap/v2/pkg/scanner"
)

// These are an opt-in starting budget, not a device-specific tuning claim.
func applyMobileDefaults(req ScanRequest) ScanRequest {
	if !req.Mobile {
		return req
	}
	if req.Workers == 0 {
		req.Workers = 32
	}
	if req.GlobalRate == 0 && !req.GlobalRateSet {
		req.GlobalRate = 100
	}
	if req.TimeoutMS == 0 && !req.GhostMode {
		req.TimeoutMS = 750
	}
	return req
}

func mobileDiscoveryOptions(opts scanner.DiscoveryOptions) scanner.DiscoveryOptions {
	opts.NumWorkers = min(opts.NumWorkers, 8)
	opts.Timeout = max(opts.Timeout, 750*time.Millisecond)
	return opts
}
