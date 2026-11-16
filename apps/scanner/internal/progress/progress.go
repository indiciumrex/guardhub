// Package progress publishes live per-check scan progress to Redis so the
// API can show the visible scan (GUARDHUB_STANDARDS §8.2). Contract:
// docs/architecture.md §2.2, hash "gh:scan:{scan_id}:progress" mapping
// check_id → queued|running|done|failed, expiring after 24h.
package progress

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// Status is a check's progress state.
type Status string

// Progress states (queued → running → done | failed).
const (
	Queued  Status = "queued"
	Running Status = "running"
	Done    Status = "done"
	Failed  Status = "failed"
)

// TTL of the progress hash.
const TTL = 24 * time.Hour

// Key returns the progress hash key for scanID.
func Key(scanID string) string { return "gh:scan:" + scanID + ":progress" }

// Tracker writes progress for scans.
type Tracker struct{ rdb redis.Cmdable }

// NewTracker returns a Tracker using rdb.
func NewTracker(rdb redis.Cmdable) *Tracker { return &Tracker{rdb: rdb} }

// Init sets every requested check to queued and sets the expiry.
func (t *Tracker) Init(ctx context.Context, scanID string, checkIDs []string) error {
	if len(checkIDs) == 0 {
		return nil
	}
	vals := make([]any, 0, 2*len(checkIDs))
	for _, id := range checkIDs {
		vals = append(vals, id, string(Queued))
	}
	key := Key(scanID)
	_, err := t.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.HSet(ctx, key, vals...)
		p.Expire(ctx, key, TTL)
		return nil
	})
	return err
}

// Set moves one check to status.
func (t *Tracker) Set(ctx context.Context, scanID, checkID string, status Status) error {
	return t.rdb.HSet(ctx, Key(scanID), checkID, string(status)).Err()
}
