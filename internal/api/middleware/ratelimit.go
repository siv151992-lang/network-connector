package middleware

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

func contextWithIP(ctx context.Context, ip netip.Addr) context.Context {
	return context.WithValue(ctx, ipKey{}, ip)
}

// Limiter is an in-memory, per-key token-bucket rate limiter. Idle buckets are
// evicted periodically so memory stays bounded under address churn.
//
// For multi-replica deployments the same interface can be backed by Redis
// (Phase 11); a single control server is the expected self-hosted setup.
type Limiter struct {
	rps     rate.Limit
	burst   int
	idleTTL time.Duration
	now     func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
	stop    chan struct{}
	once    sync.Once
}

type bucket struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

// NewLimiter creates a limiter allowing rps sustained requests per second with
// the given burst per key, and starts a janitor goroutine. Call Stop when done.
func NewLimiter(rps float64, burst int) *Limiter {
	l := &Limiter{
		rps: rate.Limit(rps), burst: burst, idleTTL: 10 * time.Minute, now: time.Now,
		buckets: map[string]*bucket{}, stop: make(chan struct{}),
	}
	go l.janitor(time.Minute)
	return l
}

// Allow consumes one token for key. When denied it returns how long until a
// token is available.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	now := l.now()
	l.mu.Lock()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{lim: rate.NewLimiter(l.rps, l.burst)}
		l.buckets[key] = b
	}
	b.lastSeen = now
	l.mu.Unlock()

	r := b.lim.ReserveN(now, 1)
	if !r.OK() {
		return false, time.Second
	}
	if d := r.DelayFrom(now); d > 0 {
		r.CancelAt(now)
		return false, d
	}
	return true, 0
}

// Len returns the number of tracked keys (for tests and metrics).
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// Stop terminates the janitor goroutine.
func (l *Limiter) Stop() { l.once.Do(func() { close(l.stop) }) }

func (l *Limiter) janitor(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
			l.evictIdle()
		}
	}
}

func (l *Limiter) evictIdle() {
	cutoff := l.now().Add(-l.idleTTL)
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
}
