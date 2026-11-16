// Package queue consumes scan and verify jobs from the Redis stream gh:jobs
// (consumer group gh-scanners), runs them and publishes results: scan
// events on gh:events and verify replies on the job's reply list. The wire
// contract is docs/architecture.md §2 (ADR-0002); this package follows it
// exactly and never touches PostgreSQL.
package queue

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hksolutions/guardhub/apps/scanner/internal/checks"
)

// Redis names from docs/architecture.md §2.
const (
	StreamJobs        = "gh:jobs"
	GroupScanners     = "gh-scanners"
	StreamEvents      = "gh:events"
	EventsMaxLen      = 10000
	VerifyReplyPrefix = "gh:verify-reply:"
	VerifyReplyTTL    = 120 * time.Second
	PayloadField      = "payload"
	ProtocolVersion   = 1
)

// Job kinds.
const (
	KindScan   = "scan"
	KindVerify = "verify"
)

// Scan deadline bounds (docs/architecture.md §3).
const (
	DefaultDeadline = 180 * time.Second
	MaxDeadline     = 300 * time.Second
)

// Job is a decoded gh:jobs payload (scan or verify).
type Job struct {
	V               int      `json:"v"`
	Kind            string   `json:"kind"`
	JobID           string   `json:"job_id"`
	ScanID          string   `json:"scan_id,omitempty"`
	Target          string   `json:"target"`
	Checks          []string `json:"checks,omitempty"`
	DeadlineSeconds int      `json:"deadline_seconds,omitempty"`
	Token           string   `json:"token,omitempty"`
	ReplyKey        string   `json:"reply_key,omitempty"`
}

// ErrMalformedJob wraps every job validation error.
var ErrMalformedJob = errors.New("malformed job")

var (
	idRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	tokenRe = regexp.MustCompile(`^[\x21-\x7e]{1,256}$`) // printable ASCII, no spaces
)

// Deadline returns the scan deadline: deadline_seconds clamped to
// (0, 300]s, defaulting to 180s.
func (j Job) Deadline() time.Duration {
	if j.DeadlineSeconds <= 0 {
		return DefaultDeadline
	}
	d := time.Duration(j.DeadlineSeconds) * time.Second
	if d > MaxDeadline {
		return MaxDeadline
	}
	return d
}

// ParseJob decodes and validates a payload. On a validation error it still
// returns whatever fields decoded, so the caller can tell the API the job
// failed (scan_id / reply_key) instead of leaving it waiting.
func ParseJob(payload string) (Job, error) {
	var j Job
	if err := json.Unmarshal([]byte(payload), &j); err != nil {
		return Job{}, fmt.Errorf("%w: invalid JSON: %w", ErrMalformedJob, err)
	}
	bad := func(format string, a ...any) (Job, error) {
		return j, fmt.Errorf("%w: "+format, append([]any{ErrMalformedJob}, a...)...)
	}
	if j.V != ProtocolVersion {
		return bad("unsupported version %d", j.V)
	}
	if !idRe.MatchString(j.JobID) {
		return bad("invalid job_id")
	}
	switch j.Kind {
	case KindScan:
		if !idRe.MatchString(j.ScanID) {
			return bad("invalid scan_id")
		}
	case KindVerify:
		if !strings.HasPrefix(j.ReplyKey, VerifyReplyPrefix) || !idRe.MatchString(strings.TrimPrefix(j.ReplyKey, VerifyReplyPrefix)) {
			return bad("reply_key must be %s<id>", VerifyReplyPrefix)
		}
		if !tokenRe.MatchString(j.Token) {
			return bad("invalid token")
		}
	default:
		return bad("unknown kind %q", j.Kind)
	}
	origin, err := checks.ParseOrigin(j.Target)
	if err != nil {
		return bad("invalid target %q", j.Target)
	}
	j.Target = origin.String()
	return j, nil
}
