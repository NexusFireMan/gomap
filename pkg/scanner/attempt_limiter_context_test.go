package scanner

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAttemptLimiterContextSharesGrants(t *testing.T) {
	l, clock, delays := virtualAttemptLimiter(10)
	if err := l.WaitContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	l.Wait()
	if len(*delays) != 1 || (*delays)[0] != 100*time.Millisecond {
		t.Fatal("Wait bypassed a context grant")
	}
	*clock = clock.Add(time.Second)
	if err := l.WaitContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	next := l.next
	if err := l.WaitContext(ctx); !errors.Is(err, context.Canceled) || l.next != next {
		t.Fatal("canceled waiter consumed a grant")
	}
	var disabled *AttemptLimiter
	if err := disabled.WaitContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("disabled limiter ignored cancellation")
	}
}

func TestAttemptLimiterContextCancelsFutureGrant(t *testing.T) {
	l := NewAttemptLimiter(1)
	l.Wait()
	next := l.next
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if err := l.WaitContext(ctx); !errors.Is(err, context.DeadlineExceeded) || next != l.next {
		t.Fatal("deadline was ignored or future grant consumed")
	}
}
