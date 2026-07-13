//go:build linux

package scanner

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/vishvananda/netlink"
)

type netlinkAddressBackend struct{}

func requireSourceIPPrivileges() error {
	if os.Geteuid() != 0 {
		return errorsNeedsRoot()
	}
	return nil
}

func errorsNeedsRoot() error {
	return errors.New("--source-ips requires root privileges; rerun gomap with sudo")
}

func newSystemAddressBackend() (interfaceAddressBackend, error) {
	return netlinkAddressBackend{}, nil
}

func (netlinkAddressBackend) List(name string) ([]*net.IPNet, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	if link.Attrs().Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("interface is down")
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	result := make([]*net.IPNet, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IPNet != nil {
			result = append(result, cloneIPNet(addr.IPNet))
		}
	}
	return result, nil
}

func (netlinkAddressBackend) Add(name string, addr *net.IPNet) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.AddrAdd(link, &netlink.Addr{IPNet: cloneIPNet(addr)})
}

func (netlinkAddressBackend) Delete(name string, addr *net.IPNet) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.AddrDel(link, &netlink.Addr{IPNet: cloneIPNet(addr)})
}

func installManagedSignalCleanup(managed *ManagedSourceIPs) func() {
	signals := make(chan os.Signal, 1)
	done := make(chan struct{})
	var stopOnce sync.Once
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case sig := <-signals:
			if err := managed.Close(); err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "gomap: source IP cleanup failed: %v\n", err)
			} else if managed.AddedCount() > 0 {
				_, _ = fmt.Fprintf(os.Stderr, "gomap: removed %d temporary source IP(s) from %s\n", managed.AddedCount(), managed.interfaceName)
			}
			if value, ok := sig.(syscall.Signal); ok {
				os.Exit(128 + int(value))
			}
			os.Exit(1)
		case <-done:
			return
		}
	}()
	return func() {
		stopOnce.Do(func() {
			signal.Stop(signals)
			close(done)
		})
	}
}
