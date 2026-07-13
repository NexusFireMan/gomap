//go:build !linux

package scanner

import "fmt"

func requireSourceIPPrivileges() error {
	return fmt.Errorf("--source-ips is currently supported only on Linux")
}

func newSystemAddressBackend() (interfaceAddressBackend, error) {
	return nil, fmt.Errorf("--source-ips is currently supported only on Linux")
}

func installManagedSignalCleanup(*ManagedSourceIPs) func() {
	return func() {}
}
