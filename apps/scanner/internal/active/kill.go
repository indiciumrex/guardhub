package active

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrKilled is returned (and logged as killed) once the global or the
// scan's kill switch is set, or when the switch cannot be read.
var ErrKilled = errors.New("active: kill switch set")

// GlobalKillKey stops every active scan; ScanKillKey(id) stops one.
const GlobalKillKey = "gh:active:kill"

// ScanKillKey is the per-scan kill switch key.
func ScanKillKey(scanID string) string { return GlobalKillKey + ":" + scanID }

// KillSwitch says whether active requests must stop now. Implementations
// fail closed: an error means "killed".
type KillSwitch interface {
	Killed(ctx context.Context) bool
}

// RedisKill reads the global and the per-scan key, caching a "not killed"
// answer for at most MaxAge (a "killed" answer is final for the scan).
type RedisKill struct {
	RDB    redis.UniversalClient
	ScanID string
	MaxAge time.Duration // default 1s (ADR-0008 §3)

	mu      sync.Mutex
	checked time.Time
	killed  bool
	now     func() time.Time
}

// Killed implements KillSwitch.
func (k *RedisKill) Killed(ctx context.Context) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.killed {
		return true
	}
	now := time.Now
	if k.now != nil {
		now = k.now
	}
	maxAge := k.MaxAge
	if maxAge <= 0 {
		maxAge = time.Second
	}
	if !k.checked.IsZero() && now().Sub(k.checked) < maxAge {
		return false
	}
	n, err := k.RDB.Exists(ctx, GlobalKillKey, ScanKillKey(k.ScanID)).Result()
	if err != nil || n > 0 {
		k.killed = true // unreadable switch = killed (fail closed)
		return true
	}
	k.checked = now()
	return false
}

// StaticKill is a KillSwitch for tests and the lab's dry runs.
type StaticKill struct {
	mu     sync.Mutex
	killed bool
}

// Kill sets the switch.
func (s *StaticKill) Kill() { s.mu.Lock(); s.killed = true; s.mu.Unlock() }

// Killed implements KillSwitch.
func (s *StaticKill) Killed(context.Context) bool { s.mu.Lock(); defer s.mu.Unlock(); return s.killed }
