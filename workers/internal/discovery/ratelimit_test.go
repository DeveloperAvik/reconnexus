package discovery

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestRateLimiterNilIsUnlimited(t *testing.T) {
	var l *rateLimiter
	if err := l.Wait(context.Background()); err != nil {
		t.Fatalf("nil limiter must be usable, got %v", err)
	}
	if lim := newRateLimiter(0); lim != nil {
		t.Fatalf("rps<=0 must yield a nil limiter, got %+v", lim)
	}
}

func TestRateLimiterPacesConcurrentRequests(t *testing.T) {
	const rps = 100.0
	lim := newRateLimiter(rps)
	interval := time.Second / rps // 10ms

	const n = 6
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = lim.Wait(context.Background())
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	// n slots span (n-1) intervals; assert a conservative lower bound (never an upper bound, so a
	// slow machine cannot make this flaky).
	if min := time.Duration(n-1) * interval * 3 / 4; elapsed < min {
		t.Fatalf("expected >= %v for %d concurrent waits at %g rps, got %v", min, n, rps, elapsed)
	}
}

func TestRateLimiterCancellation(t *testing.T) {
	lim := newRateLimiter(0.1) // 10s interval: the second slot is far away
	if err := lim.Wait(context.Background()); err != nil {
		t.Fatalf("first wait should be immediate, got %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if err := lim.Wait(ctx); err == nil {
		t.Fatal("expected a cancelled-context error")
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancelled wait should return promptly")
	}
}
