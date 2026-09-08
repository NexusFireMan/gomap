package scanner

import (
	"errors"
	"net"
	"testing"
	"time"
)

type fakeAddressBackend struct {
	existing  []*net.IPNet
	added     []*net.IPNet
	deleted   []*net.IPNet
	addError  map[string]error
	deleteErr map[string]error
}

func (f *fakeAddressBackend) List(string) ([]*net.IPNet, error) {
	return append([]*net.IPNet(nil), f.existing...), nil
}

func (f *fakeAddressBackend) Add(_ string, addr *net.IPNet) error {
	if err := f.addError[addr.String()]; err != nil {
		return err
	}
	f.added = append(f.added, cloneIPNet(addr))
	return nil
}

func (f *fakeAddressBackend) Delete(_ string, addr *net.IPNet) error {
	f.deleted = append(f.deleted, cloneIPNet(addr))
	return f.deleteErr[addr.String()]
}

func TestParseManagedSourceIPsSupportsBareAndCIDRAddresses(t *testing.T) {
	got, err := parseManagedSourceIPs("192.0.2.20, 192.0.2.21/24, 2001:db8::20/64")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"192.0.2.20/32", "192.0.2.21/24", "2001:db8::20/64"}
	if len(got) != len(want) {
		t.Fatalf("expected %d addresses, got %d", len(want), len(got))
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("address %d: expected %s, got %s", i, want[i], got[i])
		}
	}
}

func TestParseManagedSourceIPsRejectsDuplicatesAndUnsafeAddresses(t *testing.T) {
	tests := []string{
		"192.0.2.20,192.0.2.20/24",
		"0.0.0.0/32",
		"224.0.0.1/32",
		"fe80::1/64",
		"192.0.2.0/24",
		"192.0.2.255/24",
		"192.0.2.20,",
		"::ffff:192.0.2.20/120",
	}
	for _, spec := range tests {
		if _, err := parseManagedSourceIPs(spec); err == nil {
			t.Errorf("expected %q to be rejected", spec)
		}
	}
}

type blockedAddressBackend struct {
	fakeAddressBackend
	entered chan struct{}
	release chan struct{}
}

func (b *blockedAddressBackend) Add(name string, addr *net.IPNet) error {
	close(b.entered)
	<-b.release
	return b.fakeAddressBackend.Add(name, addr)
}

func TestCleanupWaitsForInFlightAddressAdd(t *testing.T) {
	b := &blockedAddressBackend{entered: make(chan struct{}), release: make(chan struct{})}
	ready := make(chan *ManagedSourceIPs, 1)
	prepared := make(chan error, 1)
	go func() {
		_, err := prepareManagedSourceIPs("fake0", "192.0.2.21/24", b, func(m *ManagedSourceIPs) { ready <- m })
		prepared <- err
	}()
	m := <-ready
	<-b.entered
	closed := make(chan error, 1)
	go func() { closed <- m.Close() }()
	select {
	case err := <-closed:
		close(b.release)
		<-prepared
		t.Fatalf("cleanup completed before the pending add: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(b.release)
	if err := <-prepared; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if len(b.deleted) != 1 || b.deleted[0].IP.String() != "192.0.2.21" {
		t.Fatalf("pending address was not cleaned: %v", b.deleted)
	}
}

func TestManagedSourceIPsAddsRequestedPoolAndCleansInReverse(t *testing.T) {
	backend := &fakeAddressBackend{
		existing: []*net.IPNet{mustIPNet(t, "192.0.2.20/24")},
	}
	managed, err := prepareManagedSourceIPsWithBackend("eth0", "192.0.2.20/24,192.0.2.21/24,192.0.2.22/24", backend)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if managed.AddedCount() != 2 {
		t.Fatalf("expected two added addresses, got %d", managed.AddedCount())
	}
	if len(managed.IPs()) != 3 {
		t.Fatalf("expected three rotation addresses, got %d", len(managed.IPs()))
	}
	if err := managed.Close(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if len(backend.deleted) != 2 || backend.deleted[0].IP.String() != "192.0.2.22" || backend.deleted[1].IP.String() != "192.0.2.21" {
		t.Fatalf("unexpected cleanup order: %v", backend.deleted)
	}
	if err := managed.Close(); err != nil {
		t.Fatalf("second cleanup should be idempotent: %v", err)
	}
	if len(backend.deleted) != 2 {
		t.Fatalf("idempotent cleanup deleted addresses again: %v", backend.deleted)
	}
}

func TestManagedSourceIPsRollsBackAfterPartialAddFailure(t *testing.T) {
	backend := &fakeAddressBackend{
		addError: map[string]error{"192.0.2.22/24": errors.New("injected add failure")},
	}
	_, err := prepareManagedSourceIPsWithBackend("eth0", "192.0.2.21/24,192.0.2.22/24", backend)
	if err == nil {
		t.Fatal("expected setup error")
	}
	if len(backend.deleted) != 1 || backend.deleted[0].IP.String() != "192.0.2.21" {
		t.Fatalf("expected first address to be rolled back, got %v", backend.deleted)
	}
}

func TestManagedSourceIPsReportsCleanupFailure(t *testing.T) {
	backend := &fakeAddressBackend{
		deleteErr: map[string]error{"192.0.2.21/24": errors.New("injected delete failure")},
	}
	managed, err := prepareManagedSourceIPsWithBackend("eth0", "192.0.2.21/24", backend)
	if err != nil {
		t.Fatalf("unexpected setup error: %v", err)
	}
	if err := managed.Close(); err == nil {
		t.Fatal("expected cleanup error")
	}
	if err := managed.Close(); err == nil {
		t.Fatal("expected idempotent close to retain the cleanup error")
	}
	if len(backend.deleted) != 1 {
		t.Fatalf("cleanup should run once, got %d delete calls", len(backend.deleted))
	}
}

func mustIPNet(t *testing.T, value string) *net.IPNet {
	t.Helper()
	ip, network, err := net.ParseCIDR(value)
	if err != nil {
		t.Fatalf("parse %s: %v", value, err)
	}
	network.IP = ip
	return network
}
