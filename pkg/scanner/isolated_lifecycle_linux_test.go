//go:build linux

package scanner

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

type signalFixtureBackend struct{ fakeAddressBackend }

func (b *signalFixtureBackend) Delete(name string, addr *net.IPNet) error {
	if _, err := fmt.Fprintln(os.Stdout, "delete "+addr.String()); err != nil {
		return err
	}
	return b.fakeAddressBackend.Delete(name, addr)
}

func TestManagedSignalCleanupChild(t *testing.T) {
	if os.Getenv("GOMAP_SIGNAL_TEST_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	b := &signalFixtureBackend{fakeAddressBackend: fakeAddressBackend{
		existing: []*net.IPNet{mustIPNet(t, "192.0.2.20/24")},
	}}
	if os.Getenv("GOMAP_SIGNAL_TEST_ERROR") == "1" {
		b.deleteErr = map[string]error{"192.0.2.22/24": errors.New("fixture cleanup failure")}
	}
	m, err := prepareManagedSourceIPsWithBackend("fake0", "192.0.2.20/24,192.0.2.21/24,192.0.2.22/24", b)
	if err != nil {
		t.Fatal(err)
	}
	m.InstallSignalCleanup()
	if _, err := fmt.Fprintln(os.Stdout, "ready"); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Hour)
	}
}

func TestManagedSignalCleanupProcess(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		for _, failure := range []bool{false, true} {
			t.Run(fmt.Sprintf("signal_%d_failure_%t", sig, failure), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestManagedSignalCleanupChild$")
				cmd.Env = append(os.Environ(), "GOMAP_SIGNAL_TEST_CHILD=1", "GOMAP_SIGNAL_TEST_ERROR=0")
				if failure {
					cmd.Env = append(cmd.Env, "GOMAP_SIGNAL_TEST_ERROR=1")
				}
				var stderr bytes.Buffer
				cmd.Stderr = &stderr
				stdout, err := cmd.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				lines := bufio.NewScanner(stdout)
				if !lines.Scan() || lines.Text() != "ready" {
					cancel()
					_ = cmd.Wait()
					t.Fatalf("child did not become ready: %v", lines.Err())
				}
				if err := cmd.Process.Signal(sig); err != nil {
					cancel()
					_ = cmd.Wait()
					t.Fatal(err)
				}
				var deleted []string
				for lines.Scan() {
					deleted = append(deleted, lines.Text())
				}
				err = cmd.Wait()
				var exit *exec.ExitError
				if ctx.Err() != nil || lines.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 128+int(sig) {
					t.Fatalf("unexpected termination: %v context=%v stderr=%s", err, ctx.Err(), stderr.String())
				}
				if strings.Join(deleted, ",") != "delete 192.0.2.22/24,delete 192.0.2.21/24" {
					t.Fatalf("cleanup missing, repeated, or removed existing address: %v", deleted)
				}
				if failure != strings.Contains(stderr.String(), "fixture cleanup failure") {
					t.Fatalf("cleanup error not reported correctly: %s", stderr.String())
				}
			})
		}
	}
}

func TestIsolatedRawSocketLifecycle(t *testing.T) {
	if os.Getenv("GOMAP_RUN_ISOLATED_TESTS") != "1" {
		t.Skip("requires an isolated Linux user/network namespace")
	}
	selfNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	initNS, err := os.Readlink("/proc/1/ns/net")
	if err != nil || selfNS == initNS {
		t.Fatal("refusing to open a raw socket outside a separate network namespace")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatalf("expected loopback-only namespace: %v %v", interfaces, err)
	}
	conn, err := net.ListenPacket("ip4:tcp", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	_, _, err = conn.ReadFrom(buffer)
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("idle raw socket did not respect its deadline: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.ReadFrom(buffer); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed raw socket remained readable: %v", err)
	}
	// Exercise native netlink error handling without adding or deleting addresses.
	if _, err := (netlinkAddressBackend{}).List("gomap-missing"); err == nil {
		t.Fatal("nonexistent interface accepted")
	}
}
