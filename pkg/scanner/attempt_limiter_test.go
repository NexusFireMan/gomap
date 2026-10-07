package scanner

import (
	"crypto/tls"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"
)

func virtualAttemptLimiter(rate int) (*AttemptLimiter, *time.Time, *[]time.Duration) {
	clock := time.Unix(0, 0)
	delays := []time.Duration{}
	l := NewAttemptLimiter(rate)
	l.now = func() time.Time { return clock }
	l.sleep = func(d time.Duration) {
		delays = append(delays, d)
		clock = clock.Add(d)
	}
	return l, &clock, &delays
}

func TestAttemptLimiterConcurrentGrantsShareBudget(t *testing.T) {
	l, clock, delays := virtualAttemptLimiter(10)
	var wg sync.WaitGroup
	for range 30 {
		wg.Go(l.Wait)
	}
	wg.Wait()
	if len(*delays) != 29 || clock.Sub(time.Unix(0, 0)) != 2900*time.Millisecond {
		t.Fatalf("unexpected concurrent budget: delays=%v time=%v", *delays, *clock)
	}
	for _, d := range *delays {
		if d != 100*time.Millisecond {
			t.Fatalf("burst or inaccurate spacing: %v", d)
		}
	}
}

func TestAttemptLimiterDisabledIdleAndRounding(t *testing.T) {
	for _, rate := range []int{0, -1} {
		l := NewAttemptLimiter(rate)
		if l != nil {
			t.Fatal("disabled limiter allocated")
		}
		l.Wait()
	}
	l, clock, delays := virtualAttemptLimiter(3)
	l.Wait()
	l.Wait()
	if (*delays)[0] != 333333334*time.Nanosecond {
		t.Fatalf("rate rounded down: %v", *delays)
	}
	*clock = clock.Add(time.Hour)
	l.Wait()
	l.Wait()
	if len(*delays) != 2 {
		t.Fatalf("idle time accumulated burst credit: %v", *delays)
	}
	if l := NewAttemptLimiter(int(^uint(0) >> 1)); l.interval < time.Nanosecond {
		t.Fatal("zero interval for large rate")
	}
}

func TestAttemptLimiterSharedAcrossHostsAndRetries(t *testing.T) {
	l, _, delays := virtualAttemptLimiter(5)
	for _, host := range []string{"192.0.2.1", "192.0.2.2"} {
		s := NewScanner(host, false)
		s.Configure(ScanConfig{AttemptLimiter: l, Retries: 2})
		s.BackoffBase = time.Nanosecond
		s.BackoffMax = time.Nanosecond
		calls := 0
		s.scanPortWithDial(80, false, func(string, time.Duration) (net.Conn, error) {
			calls++
			return nil, syscall.ETIMEDOUT
		})
		if calls != 3 {
			t.Fatalf("retry attempts=%d", calls)
		}
	}
	if len(*delays) != 5 {
		t.Fatalf("hosts or retries bypassed shared budget: %v", *delays)
	}
}

func TestAttemptLimiterCoversTransportAndDiscoveryFailures(t *testing.T) {
	l, _, delays := virtualAttemptLimiter(10)
	s := NewScanner("127.0.0.1", false)
	s.Configure(ScanConfig{AttemptLimiter: l})
	// Invalid local addresses exercise the real dial entry points without opening sockets.
	if _, err := s.dialTCP("bad-address", time.Millisecond); err == nil {
		t.Fatal("expected invalid TCP address")
	}
	if _, err := s.dialUDP("bad-address", time.Millisecond); err == nil {
		t.Fatal("expected invalid UDP address")
	}
	if _, err := s.dialTLS("bad-address", time.Millisecond, &tls.Config{MinVersion: tls.VersionTLS12}); err == nil {
		t.Fatal("expected invalid TLS address")
	}
	if isHostActive("127.0.0.1", []int{-1, -2}, time.Millisecond, nil, l) {
		t.Fatal("invalid discovery port considered active")
	}
	if len(*delays) != 4 {
		t.Fatalf("transport or discovery bypass: %v", *delays)
	}
}

func TestAttemptLimiterRechecksClockAfterShortSleep(t *testing.T) {
	l, clock, _ := virtualAttemptLimiter(10)
	l.Wait()
	calls := 0
	l.sleep = func(d time.Duration) {
		calls++
		if calls == 1 {
			d /= 2
		}
		*clock = clock.Add(d)
	}
	l.Wait()
	if calls != 2 || clock.Sub(time.Unix(0, 0)) != 100*time.Millisecond {
		t.Fatal("permit granted before its scheduled time")
	}
}

func TestAttemptLimiterLoopbackDiscoveryAndConnectCountOnce(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	port := listener.Addr().(*net.TCPAddr).Port
	l, _, delays := virtualAttemptLimiter(10)
	if !isHostActive("127.0.0.1", []int{port}, time.Second, nil, l) {
		t.Fatal("loopback discovery failed")
	}
	s := NewScanner("127.0.0.1", false)
	s.Configure(ScanConfig{AttemptLimiter: l, NumWorkers: 1})
	results := s.Scan([]int{port}, false)
	if len(results) != 1 || !results[0].IsOpen || len(*delays) != 1 {
		t.Fatalf("CONNECT was unpaced or charged twice: results=%v delays=%v", results, *delays)
	}
	conn, err := s.dialTCP(listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if len(*delays) != 2 {
		t.Fatalf("subsequent connection bypassed discovery/scan budget: %v", *delays)
	}
}
