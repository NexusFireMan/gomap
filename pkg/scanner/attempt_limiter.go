package scanner

import (
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
