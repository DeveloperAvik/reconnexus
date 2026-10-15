package discovery

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// rateLimiter paces outgoing requests to an average of one every `interval`, serialized so
// concurrent goroutines share one budget. It deliberately does not burst: the policy's
// `requestsPerSecond` is a promise to the target, so the average rate must not exceed it.
//
// A nil *rateLimiter is usable and means "no limit", so callers never need a nil check.
type rateLimiter struct {
	mu       sync.Mutex
	next     time.Time
	interval time.Duration
}

// newRateLimiter returns nil when rps <= 0 (unlimited).
func newRateLimiter(rps float64) *rateLimiter {
	if rps <= 0 {
		return nil
	}
	interval := time.Duration(float64(time.Second) / rps)
	if interval <= 0 {
		interval = time.Nanosecond
	}
	return &rateLimiter{interval: interval}
}

// Wait blocks until the next request slot, or until the context is cancelled.
func (l *rateLimiter) Wait(ctx context.Context) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	now := time.Now()
	slot := now
	if l.next.After(now) {
		slot = l.next
	}
	l.next = slot.Add(l.interval)
	l.mu.Unlock()

	d := time.Until(slot)
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// doRequest applies the job's request-rate limit before issuing a request, then performs it. The
// limiter may be nil (no limit). A cancelled context surfaces as the request error, so existing
// cancellation/timeout handling in each provider is unchanged.
func doRequest(ctx context.Context, client *http.Client, limiter *rateLimiter, req *http.Request) (*http.Response, error) {
	if err := limiter.Wait(ctx); err != nil {
		return nil, err
	}
	return client.Do(req)
}
