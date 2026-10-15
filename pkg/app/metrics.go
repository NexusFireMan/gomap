package app

import "github.com/NexusFireMan/gomap/v2/pkg/output"

func newScanMetrics(req ScanRequest, expandedHosts int) output.ScanMetrics {
	build := req.Build
	if build.Version == "" {
		build.Version = "unknown"
	}
	return output.ScanMetrics{
		Build: build, ExpandedHosts: expandedHosts, Hosts: []output.HostMetrics{},
		Options: output.ScanOptions{
			ScanType: req.ScanType, UDP: req.UDP, Ports: req.PortsFlag,
			TopPorts: req.TopPorts, ExcludePorts: req.ExcludePorts, NoDiscovery: req.NoDiscovery,
			MaxHosts: req.MaxHosts, ServiceDetect: req.ServiceDetect, DeepVersion: req.DeepVersion,
			Exhaustive: req.Exhaustive, GhostMode: req.GhostMode, Workers: req.Workers,
			TimeoutMS: req.TimeoutMS, Retries: req.Retries, AdaptiveTimeout: req.AdaptiveTimeout,
			MaxTimeoutMS: req.MaxTimeoutMS, BackoffMS: req.BackoffMS, Rate: req.Rate, GlobalRate: req.GlobalRate,
		},
	}
}
