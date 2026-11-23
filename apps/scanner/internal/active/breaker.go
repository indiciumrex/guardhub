package active

import (
	"errors"
	"sort"
	"sync"
	"time"
)

// ErrBreaker is returned (and logged as breaker) once the target shows
// stress: the scan stops (ADR-0008 §4).
var ErrBreaker = errors.New("active: target under stress, scan stopped")

// ErrBudget is returned (and logged as budget) past the scan's or the
// module's request budget.
var ErrBudget = errors.New("active: request budget exhausted")

// Limits are the do-no-harm limits of one active scan.
type Limits struct {
	RPS             float64       // requests per second to the target (default 1)
	ScanBudget      int           // requests per scan (default 300)
	ModuleBudget    int           // requests per module (default 100)
	MaxConsecutive5 int           // consecutive 5xx answers that stop the scan (default 3)
	LatencyFactor   float64       // median of the last 10 above factor x baseline stops it (default 3)
	MaxRetryAfter   time.Duration // a longer Retry-After stops the scan (default 30s)
}

// DefaultLimits are ADR-0008 §4's values.
func DefaultLimits() Limits {
	return Limits{RPS: 1, ScanBudget: 300, ModuleBudget: 100, MaxConsecutive5: 3, LatencyFactor: 3, MaxRetryAfter: 30 * time.Second}
}

// breaker tracks the target's answers and trips on stress.
type breaker struct {
	mu        sync.Mutex
	lim       Limits
	baseline  time.Duration
	recent    []time.Duration
	consec5xx int
	answered  bool
	tripped   bool
}

// observe records one answer (status 0 = connection failure) and reports
// whether the breaker is (now) tripped.
func (b *breaker) observe(status int, latency time.Duration) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tripped {
		return true
	}
	switch {
	case status == 0:
		if b.answered {
			b.tripped = true // the target answered before and now does not
		}
		return b.tripped
	case status >= 500:
		b.consec5xx++
		if b.consec5xx >= b.lim.MaxConsecutive5 {
			b.tripped = true
		}
	default:
		b.consec5xx = 0
	}
	b.answered = true
	if b.baseline == 0 {
		b.baseline = max(latency, 50*time.Millisecond)
	}
	b.recent = append(b.recent, latency)
	if len(b.recent) > 10 {
		b.recent = b.recent[1:]
	}
	if len(b.recent) == 10 {
		s := append([]time.Duration(nil), b.recent...)
		sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
		if med := (s[4] + s[5]) / 2; float64(med) > b.lim.LatencyFactor*float64(b.baseline) {
			b.tripped = true
		}
	}
	return b.tripped
}

func (b *breaker) trip() { b.mu.Lock(); b.tripped = true; b.mu.Unlock() }

func (b *breaker) isTripped() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.tripped }
