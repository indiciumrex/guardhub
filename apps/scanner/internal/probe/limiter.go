package probe

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// limiterIdleTTL: per-host limiters unused for this long are dropped so the
// map stays bounded in a long-running process.
const limiterIdleTTL = 10 * time.Minute

// Limiters holds one token bucket per host. Share one instance across all
// clients of a process so concurrent scans of the same host respect a single
// rate limit.
type Limiters struct {
	rps   rate.Limit
	burst int

	mu      sync.Mutex
	hosts   map[string]*hostLimiter
	lastGC  time.Time
	nowFunc func() time.Time
}

type hostLimiter struct {
	lim      *rate.Limiter
	lastUsed time.Time
}

// NewLimiters creates a per-host limiter set allowing rps requests per second
// with the given burst.
func NewLimiters(rps float64, burst int) *Limiters {
	if rps <= 0 {
		rps = DefaultHostRPS
	}
	if burst <= 0 {
		burst = DefaultHostBurst
	}
	return &Limiters{
		rps:     rate.Limit(rps),
		burst:   burst,
		hosts:   make(map[string]*hostLimiter),
		nowFunc: time.Now,
	}
}

// Wait blocks until host may receive another request or ctx is done.
func (l *Limiters) Wait(ctx context.Context, host string) error {
	return l.get(host).Wait(ctx)
}

func (l *Limiters) get(host string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.nowFunc()
	if now.Sub(l.lastGC) > limiterIdleTTL {
		for h, hl := range l.hosts {
			if now.Sub(hl.lastUsed) > limiterIdleTTL {
				delete(l.hosts, h)
			}
		}
		l.lastGC = now
	}
	hl, ok := l.hosts[host]
	if !ok {
		hl = &hostLimiter{lim: rate.NewLimiter(l.rps, l.burst)}
		l.hosts[host] = hl
	}
	hl.lastUsed = now
	return hl.lim
}

// Len returns the number of tracked hosts (for tests and metrics).
func (l *Limiters) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.hosts)
}
