package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/hksolutions/guardhub/apps/scanner/internal/active"
	"github.com/hksolutions/guardhub/apps/scanner/internal/activescan"
	"github.com/hksolutions/guardhub/apps/scanner/internal/checks"
	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/progress"
)

// KindActiveScan runs the active checks (ADR-0008) against one verified,
// consented origin. Refused unless the scanner runs with
// SCANNER_ACTIVE_ENABLED=true (ActiveConfig.Enabled), which is off everywhere
// until the founder's checkpoint (ADR-0008 §8).
const KindActiveScan = "active_scan"

// ActiveSessionPrefix is the one-time Redis key holding the consented test
// accounts of an active scan (gh:active-sessions:<job_id>, read with GETDEL;
// never in the stream, never logged).
const ActiveSessionPrefix = "gh:active-sessions:"

// Active scan deadlines: longer than a passive scan (1 request/s).
const (
	DefaultActiveDeadline = 10 * time.Minute
	MaxActiveDeadline     = 15 * time.Minute
	maxExcludedPaths      = 20
)

// EventActiveRequestLog carries an active scan's request log to the API
// (the append-only active_request_log table), before scan.completed/failed.
const EventActiveRequestLog = "active.request_log"

// Active scan error codes (scan.failed and check_results).
const (
	ErrCodeActiveDisabled    = "active_disabled"    // this scanner does not run active scans
	ErrCodeActiveKilled      = "active_killed"      // the kill switch is set (global or this scan)
	ErrCodeOwnershipUnproven = "ownership_unproven" // fresh ownership proof failed at scan start
	ErrCodeTargetStressed    = "target_stressed"    // circuit breaker: errors, slowness or a long Retry-After
)

// ActiveConfig configures active scans.
type ActiveConfig struct {
	Enabled           bool                // SCANNER_ACTIVE_ENABLED=true; false refuses every active_scan job
	Collab            active.Collaborator // nil: SSRF is not run
	Limits            active.Limits       // zero: active.DefaultLimits()
	AllowPrivateHosts []string            // lab only
	// NewKill returns the scan's kill switch (default: RedisKill on s.RDB).
	NewKill func(scanID string) active.KillSwitch
}

// ActiveRequestLog is the active.request_log event.
type ActiveRequestLog struct {
	V         int               `json:"v"`
	Type      string            `json:"type"`
	ScanID    string            `json:"scan_id"`
	ConsentID string            `json:"consent_id"`
	At        string            `json:"at"`
	Entries   []active.LogEntry `json:"entries"`
}

// activeSessions is the JSON stored under ActiveSessionPrefix+job_id.
type activeSessions struct {
	A *active.Session `json:"a"`
	B *active.Session `json:"b"`
}

// ActiveDeadline returns the active scan deadline (default 10 min, max 15).
func (j Job) ActiveDeadline() time.Duration {
	if j.DeadlineSeconds <= 0 {
		return DefaultActiveDeadline
	}
	return min(time.Duration(j.DeadlineSeconds)*time.Second, MaxActiveDeadline)
}

// validateActiveJob is ParseJob's active_scan branch.
func validateActiveJob(j Job) error {
	if !idRe.MatchString(j.ScanID) {
		return errors.New("invalid scan_id")
	}
	if !idRe.MatchString(j.ConsentID) {
		return errors.New("invalid consent_id")
	}
	if !tokenRe.MatchString(j.Token) {
		return errors.New("invalid ownership token")
	}
	if len(j.Checks) == 0 {
		return errors.New("no checks")
	}
	for _, id := range j.Checks {
		if !evidence.ActiveChecks[id] {
			return fmt.Errorf("not an active check: %q", id)
		}
	}
	if len(j.Exclude) > maxExcludedPaths {
		return errors.New("too many excluded paths")
	}
	for _, p := range j.Exclude {
		if !strings.HasPrefix(p, "/") || len(p) > 512 || strings.ContainsAny(p, "\r\n?#") {
			return fmt.Errorf("invalid excluded path %q", p)
		}
	}
	if j.SessionKey != "" && j.SessionKey != ActiveSessionPrefix+j.JobID {
		return fmt.Errorf("session_key must be %s<job_id>", ActiveSessionPrefix)
	}
	return nil
}

// runActiveScan: refuse when disabled or killed, re-prove ownership now,
// then discovery and the requested checks one after another through the
// fenced client. Every request is in the request log the API stores.
func (s *Service) runActiveScan(jobCtx context.Context, job Job) error {
	log := s.log().With("job_id", job.JobID, "scan_id", job.ScanID, "target", job.Target, "consent_id", job.ConsentID)
	// the sessions are taken (and so deleted) first, whatever happens next
	sessions, serr := s.takeActiveSessions(jobCtx, job)
	fail := func(code string) error {
		log.Info("active scan refused or stopped", "error_code", code)
		if err := publishEvent(jobCtx, s.RDB, ScanFailed{V: ProtocolVersion, Type: EventScanFailed, ScanID: job.ScanID,
			At: rfc3339(s.now()), Error: code}); err != nil {
			return fmt.Errorf("publish scan.failed: %w", err)
		}
		return nil
	}
	if !s.Active.Enabled {
		return fail(ErrCodeActiveDisabled)
	}
	if serr != nil {
		log.Warn("active sessions unreadable", "err", serr)
		return fail(ErrCodeInternal)
	}
	kill := s.activeKill(job.ScanID)
	if kill.Killed(jobCtx) {
		return fail(ErrCodeActiveKilled)
	}
	if err := publishEvent(jobCtx, s.RDB, ScanStarted{V: ProtocolVersion, Type: EventScanStarted, ScanID: job.ScanID, At: rfc3339(s.now())}); err != nil {
		return fmt.Errorf("publish scan.started: %w", err)
	}

	// ADR-0008 §2: ownership is proven again at the start of every active
	// scan, trusted domains included (no cached proof).
	origin, _ := checks.ParseOrigin(job.Target) // validated by ParseJob
	vctx, vcancel := context.WithTimeout(jobCtx, s.verifyDeadline())
	vclient := s.NewVerifyProbe()
	proof := verifyOwnership(vctx, vclient, origin.Scheme+"://"+origin.Host, strings.ToLower(origin.Hostname()), job.Token)
	vclient.Close()
	vcancel()
	if jobCtx.Err() != nil {
		return errShutdown
	}
	if proof.method == "" {
		return fail(ErrCodeOwnershipUnproven)
	}

	scope, err := active.NewScope(job.Target, job.Exclude)
	if err != nil {
		return fail(ErrCodeInternal)
	}
	reqLog := &active.RequestLog{}
	client, err := active.NewClient(active.Options{Scope: scope, Kill: kill, Log: reqLog, Limits: s.Active.Limits,
		AllowPrivateHosts: s.Active.AllowPrivateHosts, InsecureTLS: true})
	if err != nil {
		return fail(ErrCodeInternal)
	}
	scanCtx, cancel := context.WithTimeout(jobCtx, job.ActiveDeadline())
	defer cancel()

	findings, results := runActiveChecks(scanCtx, client, scope, job.Checks, sessions, s.Active.Collab)
	if jobCtx.Err() != nil {
		return errShutdown
	}
	if err := publishEvent(jobCtx, s.RDB, ActiveRequestLog{V: ProtocolVersion, Type: EventActiveRequestLog, ScanID: job.ScanID,
		ConsentID: job.ConsentID, At: rfc3339(s.now()), Entries: reqLog.Entries()}); err != nil {
		return fmt.Errorf("publish active.request_log: %w", err)
	}
	ev := ScanCompleted{V: ProtocolVersion, Type: EventScanCompleted, ScanID: job.ScanID, At: rfc3339(s.now()),
		Findings: findings, CheckResults: results}
	if err := publishEvent(jobCtx, s.RDB, ev); err != nil {
		return fmt.Errorf("publish scan.completed: %w", err)
	}
	log.Info("active scan completed", "findings", len(findings), "requests", client.Sent(), "ownership", proof.method)
	return nil
}

// runActiveChecks is activescan.Run with the scan's error codes (shared with
// the lab harness, cmd/scanner activelab).
func runActiveChecks(ctx context.Context, client *active.Client, scope active.Scope, ids []string,
	sessions activeSessions, collab active.Collaborator) ([]evidence.Finding, []CheckResult) {
	findings, outs := activescan.Run(ctx, client, scope, ids, sessions.A, sessions.B, collab)
	results := make([]CheckResult, 0, len(outs))
	for _, o := range outs {
		switch {
		case o.Err == nil:
			results = append(results, CheckResult{CheckID: o.CheckID, Status: string(progress.Done)})
		case errors.Is(o.Err, activescan.ErrUnknownCheck):
			results = append(results, CheckResult{CheckID: o.CheckID, Status: string(progress.Failed), Error: strPtr(ErrCodeUnknownCheck)})
		default:
			results = append(results, CheckResult{CheckID: o.CheckID, Status: string(progress.Failed), Error: strPtr(activeErrCode(ctx, o.Err))})
		}
	}
	return findings, results
}

func activeErrCode(ctx context.Context, err error) string {
	switch {
	case errors.Is(err, active.ErrKilled) && ctx.Err() == nil:
		return ErrCodeActiveKilled
	case ctx.Err() != nil:
		return ErrCodeTimeout
	case errors.Is(err, active.ErrBreaker):
		return ErrCodeTargetStressed
	case errors.Is(err, active.ErrBudget):
		return ErrCodeBudgetExceeded
	}
	return ErrCodeInternal
}

func (s *Service) activeKill(scanID string) active.KillSwitch {
	if s.Active.NewKill != nil {
		return s.Active.NewKill(scanID)
	}
	return &active.RedisKill{RDB: s.RDB, ScanID: scanID}
}

// takeActiveSessions reads and deletes the job's consented test accounts
// (none: IDOR stays silent). A present but invalid record is an error.
func (s *Service) takeActiveSessions(ctx context.Context, job Job) (activeSessions, error) {
	var out activeSessions
	if job.SessionKey == "" {
		return out, nil
	}
	raw, err := s.RDB.GetDel(ctx, job.SessionKey).Result()
	if errors.Is(err, redis.Nil) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return activeSessions{}, errors.New("malformed sessions record")
	}
	for _, sess := range []*active.Session{out.A, out.B} {
		if sess != nil {
			if err := sess.Validate(); err != nil {
				return activeSessions{}, err
			}
		}
	}
	return out, nil
}
