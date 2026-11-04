package scanner

import (
	"context"
	"sync"
	"time"
)

// AttemptLimiter spaces connection/probe starts across all scan phases and hosts.
// It does not count packets or messages exchanged on an established connection.
type AttemptLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
	now      func() time.Time
	sleep    func(time.Duration)
}

// WaitContext shares the same grants as Wait but never blocks on its mutex or
// timer past cancellation. Existing uncancelable callers retain their behavior.
func (l *AttemptLimiter) WaitContext(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if l == nil {
			return nil
		}
		if !l.mu.TryLock() {
			if err := waitAttemptContext(ctx, time.Millisecond); err != nil {
				return err
			}
			continue
		}
		delay := l.next.Sub(l.now())
		if delay <= 0 {
			err := ctx.Err()
			if err == nil {
				l.next = l.now().Add(l.interval)
			}
			l.mu.Unlock()
			return err
		}
		l.mu.Unlock()
		if err := waitAttemptContext(ctx, delay); err != nil {
			return err
		}
	}
}

func waitAttemptContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}

// NewAttemptLimiter returns a shared budget, or nil when rate is disabled.
func NewAttemptLimiter(rate int) *AttemptLimiter {
	if rate <= 0 {
		return nil
	}
	return &AttemptLimiter{
		interval: (time.Second-1)/time.Duration(rate) + 1,
		now:      time.Now,
		sleep:    time.Sleep,
	}
}

// Wait grants one attempt. A nil limiter leaves existing pacing unchanged.
func (l *AttemptLimiter) Wait() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	// Serialize grants without a ticker, background goroutine, or burst credit.
	for delay := l.next.Sub(l.now()); delay > 0; delay = l.next.Sub(l.now()) {
		l.sleep(delay)
	}
	l.next = l.now().Add(l.interval)
}
