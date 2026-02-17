package gomap

import (
	"errors"
	"fmt"
	"os"

	"github.com/NexusFireMan/gomap/pkg/app"
	"github.com/NexusFireMan/gomap/pkg/output"
)

func Run() {
	opts, err := ParseCLIOptions(os.Args[1:])
	if err != nil {
		if errors.Is(err, errUsage) {
			os.Exit(1)
		}
		fmt.Printf("%s\n", output.StatusError(err.Error()))
		os.Exit(1)
	}

	if opts.VersionFlag {
		PrintVersion()
		os.Exit(0)
	}

	if opts.RemoveFlag {
		if err := RemoveGomap(); err != nil {
			fmt.Printf("%s\n", output.StatusError(fmt.Sprintf("Removal failed: %v", err)))
			os.Exit(1)
		}
		os.Exit(0)
	}

	if opts.UpdateFlag {
		if err := CheckUpdate(); err != nil {
			fmt.Printf("%s\n", output.StatusError(fmt.Sprintf("Update failed: %v", err)))
			PrintUpdateInfo()
			os.Exit(1)
		}
		os.Exit(0)
	}

	req := app.ScanRequest{
		Target:          opts.Host,
		PortsFlag:       opts.PortsFlag,
		ExcludePorts:    opts.ExcludePorts,
		TopPorts:        opts.TopPorts,
		Rate:            opts.Rate,
		MaxHosts:        opts.MaxHosts,
		ServiceDetect:   opts.ServiceFlag,
		GhostMode:       opts.GhostFlag,
		NoDiscovery:     opts.NoDiscovery,
		Format:          opts.FormatFlag,
		OutputPath:      opts.OutPath,
		TimeoutMS:       opts.TimeoutMS,
		Workers:         opts.Workers,
		Retries:         opts.Retries,
		BackoffMS:       opts.BackoffMS,
		MaxTimeoutMS:    opts.MaxTimeoutMS,
		AdaptiveTimeout: opts.AdaptiveTimeout,
		Details:         opts.DetailsFlag,
	}

	if err := app.ExecuteScan(req); err != nil {
		fmt.Printf("%s\n", output.StatusError(err.Error()))
		os.Exit(1)
	}
}
