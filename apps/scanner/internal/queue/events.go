package queue

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
)

// Event types on gh:events (docs/architecture.md §2.3).
const (
	EventScanStarted   = "scan.started"
	EventScanCompleted = "scan.completed"
	EventScanFailed    = "scan.failed"
)

// scan.failed error codes.
const (
	ErrCodeTargetUnreachable = "target_unreachable"
	ErrCodeTargetBlocked     = "target_blocked"
	ErrCodeTimeout           = "timeout"
	ErrCodeInternal          = "internal"
	// Repo scans (ADR-0006).
	ErrCodeRepoAccessLost = "repo_access_lost" // the token cannot read the repository
	ErrCodeRepoEmpty      = "repo_empty"       // no commits yet
)

// check_results error codes (in addition to the scan.failed codes).
const (
	ErrCodeUnknownCheck   = "unknown_check"
	ErrCodeBudgetExceeded = "budget_exceeded"
	// Repo checks: the snapshot hit a cap (partial results are kept).
	ErrCodeRepoTooLarge = "repo_too_large"
	// dependency_vulns: OSV could not be asked, or a lockfile was unreadable.
	ErrCodeAdvisoryDBUnavailable = "advisory_db_unavailable"
	ErrCodeManifestUnreadable    = "manifest_unreadable"
)

// ScanStarted is the scan.started event.
type ScanStarted struct {
	V      int    `json:"v"`
	Type   string `json:"type"`
	ScanID string `json:"scan_id"`
	At     string `json:"at"`
}

// CheckResult is one entry of scan.completed check_results.
type CheckResult struct {
	CheckID string  `json:"check_id"`
	Status  string  `json:"status"`
	Error   *string `json:"error"`
}

// ScanCompleted is the scan.completed event.
type ScanCompleted struct {
	V            int                `json:"v"`
	Type         string             `json:"type"`
	ScanID       string             `json:"scan_id"`
	At           string             `json:"at"`
	Findings     []evidence.Finding `json:"findings"`
	CheckResults []CheckResult      `json:"check_results"`
}

// ScanFailed is the scan.failed event.
type ScanFailed struct {
	V      int    `json:"v"`
	Type   string `json:"type"`
	ScanID string `json:"scan_id"`
	At     string `json:"at"`
	Error  string `json:"error"`
}

// VerifyReply is pushed to the verify job's reply_key.
type VerifyReply struct {
	V        int     `json:"v"`
	JobID    string  `json:"job_id"`
	Verified bool    `json:"verified"`
	Method   *string `json:"method"`
	Error    *string `json:"error"`
}

// Verify methods and errors (docs/architecture.md §2.1).
const (
	MethodWellKnown = "well_known"
	MethodMetaTag   = "meta_tag"
	MethodDNSTXT    = "dns_txt"

	VerifyErrNotFound    = "not_found"
	VerifyErrUnreachable = "target_unreachable"
	VerifyErrBlocked     = "target_blocked"
	VerifyErrTimeout     = "timeout"
)

func strPtr(s string) *string { return &s }

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// publishEvent appends ev to gh:events (MAXLEN ~ 10000).
func publishEvent(ctx context.Context, rdb redis.Cmdable, ev any) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	return rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: StreamEvents,
		MaxLen: EventsMaxLen,
		Approx: true,
		Values: map[string]any{PayloadField: string(b)},
	}).Err()
}

// pushVerifyReply does LPUSH reply_key + EXPIRE 120 atomically.
func pushVerifyReply(ctx context.Context, rdb redis.Cmdable, key string, r VerifyReply) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.LPush(ctx, key, string(b))
		p.Expire(ctx, key, VerifyReplyTTL)
		return nil
	})
	return err
}
