package scanner

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestConnectContextStatesAndClose(t *testing.T) {
	var closes atomic.Int32
	observed := make(map[int]ScanResult)
	summary, err := scanConnectContext(context.Background(), "127.0.0.1", []int{21, 22, 23, 24, 21}, ConnectOptions{Workers: 2, Rate: 1000}, func(r ScanResult) error { observed[r.Port] = r; return nil }, func(_ context.Context, addr string, timeout time.Duration) (net.Conn, error) {
		_, text, _ := net.SplitHostPort(addr)
		if timeout != 750*time.Millisecond {
			t.Errorf("unexpected timeout: %v", timeout)
		}
		switch text {
		case "21":
			return countedScanConn{closes: &closes}, nil
		case "22":
			return nil, syscall.ECONNREFUSED
		case "23":
			return nil, os.ErrDeadlineExceeded
		default:
			return nil, syscall.EHOSTUNREACH
		}
	})
	if err != nil || summary.Requested != 4 || summary.Completed != 4 || summary.Open != 1 || summary.Closed != 1 || summary.Filtered != 1 || summary.Unknown != 1 || summary.Unreported != 0 || summary.Cancelled || closes.Load() != 1 {
		t.Fatalf("incorrect observations: %+v err=%v closes=%d", summary, err, closes.Load())
	}
	for port, state := range map[int]string{21: "open", 22: "closed", 23: "filtered", 24: "unknown"} {
		if observed[port].State != state || observed[port].Evidence == "" {
			t.Fatalf("missing evidence/state: %+v", observed[port])
		}
	}
	if observed[21].ServiceName != "ftp" || observed[21].Confidence != "low" || observed[21].Version != "" {
		t.Fatal("port hint became a confirmed fingerprint")
	}
}

func TestConnectContextCancelJoinsWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{}, 4)
	finished := make(chan struct{})
	var active atomic.Int32
	var summary ConnectSummary
	var runErr error
	go func() {
		defer close(finished)
		summary, runErr = scanConnectContext(ctx, "::1", []int{1, 2, 3, 4, 5, 6, 7, 8}, ConnectOptions{Workers: 4, Rate: 1000}, func(ScanResult) error { t.Error("cancelled dial was reported"); return nil }, func(ctx context.Context, _ string, _ time.Duration) (net.Conn, error) {
			active.Add(1)
			defer active.Add(-1)
			entered <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		})
	}()
	for range 4 {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("workers failed to start")
		}
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("cancel did not join workers")
	}
	if !errors.Is(runErr, context.Canceled) || active.Load() != 0 || summary.Completed != 0 || summary.Unreported != 8 || !summary.Cancelled {
		t.Fatalf("cancel misreported coverage: %+v %v", summary, runErr)
	}
}

func TestConnectContextCancelPacingAndConsumerFailure(t *testing.T) {
	for _, consumerFailure := range []bool{false, true} {
		t.Run(strconv.FormatBool(consumerFailure), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stop := errors.New("consumer stopped")
			var closes atomic.Int32
			finished := make(chan struct{})
			var summary ConnectSummary
			var runErr error
			go func() {
				defer close(finished)
				summary, runErr = scanConnectContext(ctx, "127.0.0.1", []int{1, 2, 3, 4}, ConnectOptions{Rate: 1}, func(ScanResult) error {
					if consumerFailure {
						return stop
					}
					cancel()
					return nil
				}, func(context.Context, string, time.Duration) (net.Conn, error) {
					return countedScanConn{closes: &closes}, nil
				})
			}()
			select {
			case <-finished:
			case <-time.After(3 * time.Second):
				t.Fatal("cancel failed to interrupt limiter")
			}
			want := context.Canceled
			if consumerFailure {
				want = stop
			}
			if !errors.Is(runErr, want) || summary.Completed > 1 || summary.Requested != 4 || summary.Unreported != 4-summary.Completed || closes.Load() != 1 {
				t.Fatalf("lost cleanup/partial coverage: %+v %v", summary, runErr)
			}
		})
	}
}

func TestConnectContextValidationAndPreCancel(t *testing.T) {
	for _, host := range []string{"fixture.invalid", "127.0.0.1/24", "0.0.0.0", "255.255.255.255", "ff02::1", "fe80::1%eth0"} {
		if _, err := ScanConnectContext(context.Background(), host, []int{80}, ConnectOptions{}, func(ScanResult) error { return nil }); err == nil {
			t.Fatalf("accepted %s", host)
		}
	}
	for _, opts := range []ConnectOptions{{Workers: -1}, {Workers: 129}, {Rate: -1}, {Rate: 1001}, {Timeout: time.Nanosecond}, {Timeout: 11 * time.Second}} {
		if _, err := ScanConnectContext(context.Background(), "127.0.0.1", []int{80}, opts, func(ScanResult) error { return nil }); err == nil {
			t.Fatal("accepted invalid limits")
		}
	}
	for _, ports := range [][]int{{0}, {65536}} {
		if _, err := ScanConnectContext(context.Background(), "127.0.0.1", ports, ConnectOptions{}, func(ScanResult) error { return nil }); err == nil {
			t.Fatal("accepted invalid port")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	summary, err := scanConnectContext(ctx, "127.0.0.1", []int{80}, ConnectOptions{}, func(ScanResult) error { t.Error("unexpected callback"); return nil }, func(context.Context, string, time.Duration) (net.Conn, error) {
		t.Error("unexpected dial")
		return nil, context.Canceled
	})
	if !errors.Is(err, context.Canceled) || summary.Unreported != 1 || !summary.Cancelled {
		t.Fatalf("invalid precancel: %+v %v", summary, err)
	}
	for _, invalid := range []struct {
		ctx      context.Context
		consumer func(ScanResult) error
	}{
		{consumer: func(ScanResult) error { return nil }},
		{ctx: context.Background()},
	} {
		if _, err := ScanConnectContext(invalid.ctx, "127.0.0.1", nil, ConnectOptions{}, invalid.consumer); err == nil {
			t.Fatal("accepted missing context or callback")
		}
	}
	summary, err = ScanConnectContext(context.Background(), "127.0.0.1", nil, ConnectOptions{}, func(ScanResult) error { return nil })
	if err != nil || summary.Requested != 0 || summary.Completed != 0 {
		t.Fatal(summary, err)
	}
}
