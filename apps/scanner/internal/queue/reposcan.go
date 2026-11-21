package queue

// Repo scans (ADR-0006): the API enqueues a repo_scan job naming the
// repository and a one-time Redis key that holds an installation token
// narrowed to that repository (contents:read). The scanner takes the token
// with GETDEL, reads the default branch into memory, runs the repo checks,
// publishes the usual scan events and revokes the token, success or not.
// Nothing is written to disk; only findings leave.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/hksolutions/guardhub/apps/scanner/internal/checks"
	"github.com/hksolutions/guardhub/apps/scanner/internal/deps"
	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/pool"
	"github.com/hksolutions/guardhub/apps/scanner/internal/progress"
	"github.com/hksolutions/guardhub/apps/scanner/internal/repo"
)

// RepoScanConfig configures repo scans.
type RepoScanConfig struct {
	GitHubAPI string            // "" = https://api.github.com
	Transport http.RoundTripper // egress transport with the IP guard
	Timeout   time.Duration     // per GitHub request (the tarball read included)
	Limits    repo.Limits
	// Slots bounds concurrent repo scans in this process (snapshots are
	// held in memory). Nil = one at a time.
	Slots chan struct{}
}

func (c RepoScanConfig) api() string {
	if c.GitHubAPI == "" {
		return repo.DefaultGitHubAPI
	}
	return c.GitHubAPI
}

// repoSlots is the default process-wide limiter (one repo scan at a time).
var repoSlots = make(chan struct{}, 1)

func (s *Service) runRepoScan(jobCtx context.Context, job Job) error {
	log := s.log().With("job_id", job.JobID, "scan_id", job.ScanID, "repo", job.Repo)
	if s.RepoRegistry == nil {
		log.Error("repo scan received but repo scanning is not configured")
		return s.failRepoScan(jobCtx, nil, job, ErrCodeInternal, log)
	}
	slots := s.Repo.Slots
	if slots == nil {
		slots = repoSlots
	}
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	case <-jobCtx.Done():
		return errShutdown
	}

	// The token is taken exactly once. A redelivered job finds it gone and
	// fails (the user re-runs the scan): a token is never reused or kept.
	token, err := s.RDB.GetDel(jobCtx, job.TokenKey).Result()
	if err != nil || token == "" {
		if jobCtx.Err() != nil {
			return errShutdown
		}
		if !errors.Is(err, redis.Nil) && err != nil {
			log.Warn("reading the repo token failed", "err", err)
		}
		return s.failRepoScan(jobCtx, nil, job, ErrCodeInternal, log)
	}
	gh := repo.NewGitHub(s.Repo.api(), token, s.Repo.Transport, s.Repo.Timeout)
	defer func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(jobCtx), 10*time.Second)
		defer cancel()
		if err := gh.Revoke(ctx); err != nil {
			log.Warn("revoking the repo token failed (it expires within the hour)", "err", err)
		}
	}()

	if err := publishEvent(jobCtx, s.RDB, ScanStarted{V: ProtocolVersion, Type: EventScanStarted, ScanID: job.ScanID, At: rfc3339(s.now())}); err != nil {
		return fmt.Errorf("publish scan.started: %w", err)
	}
	tracker := progress.NewTracker(s.RDB)
	if err := tracker.Init(jobCtx, job.ScanID, job.Checks); err != nil {
		log.Warn("progress init failed", "err", err)
	}
	scanCtx, cancel := context.WithTimeout(jobCtx, job.Deadline())
	defer cancel()

	snap, err := gh.Snapshot(scanCtx, job.Repo, s.Repo.Limits)
	if err != nil {
		if jobCtx.Err() != nil {
			return errShutdown
		}
		code := classifyRepoError(scanCtx, err)
		log.Info("repo scan cannot run", "error_code", code, "err", err)
		return s.failRepoScan(jobCtx, tracker, job, code, log)
	}
	findings, results := s.runRepoChecks(scanCtx, jobCtx, tracker, job, snap, log)
	if jobCtx.Err() != nil {
		return errShutdown
	}
	ev := ScanCompleted{V: ProtocolVersion, Type: EventScanCompleted, ScanID: job.ScanID, At: rfc3339(s.now()),
		Findings: findings, CheckResults: results}
	if err := publishEvent(jobCtx, s.RDB, ev); err != nil {
		return fmt.Errorf("publish scan.completed: %w", err)
	}
	log.Info("repo scan completed", "findings", len(findings), "files", len(snap.Files),
		"truncated", snap.Truncated, "skipped_large", snap.SkippedLarge)
	return nil
}

// RunRepoChecks runs the given repo checks on a snapshot (lab and tests).
func (s *Service) RunRepoChecks(ctx context.Context, snap *repo.Snapshot, ids []string) ([]evidence.Finding, []CheckResult) {
	job := Job{ScanID: "local", Checks: ids}
	return s.runRepoChecks(ctx, ctx, nil, job, snap, s.log())
}

func (s *Service) runRepoChecks(ctx, jobCtx context.Context, tracker *progress.Tracker, job Job, snap *repo.Snapshot, log *slog.Logger) ([]evidence.Finding, []CheckResult) {
	outcomes := make([]checkOutcome, len(job.Checks))
	for i, id := range job.Checks {
		outcomes[i] = checkOutcome{result: CheckResult{CheckID: id, Status: string(progress.Failed), Error: strPtr(ErrCodeTimeout)}}
	}
	pool.ForEach(ctx, len(job.Checks), len(job.Checks), func(ctx context.Context, i int) {
		outcomes[i] = s.runRepoCheck(ctx, jobCtx, tracker, job, job.Checks[i], snap, log)
	})
	findings := []evidence.Finding{}
	results := make([]CheckResult, 0, len(outcomes))
	for _, o := range outcomes {
		findings = append(findings, o.findings...)
		results = append(results, o.result)
	}
	return findings, results
}

func (s *Service) runRepoCheck(ctx, jobCtx context.Context, tracker *progress.Tracker, job Job, id string, snap *repo.Snapshot, log *slog.Logger) (out checkOutcome) {
	out.result = CheckResult{CheckID: id, Status: string(progress.Done)}
	setProgress := func(st progress.Status) {
		if tracker != nil {
			s.setProgress(jobCtx, tracker, job.ScanID, id, st, log)
		}
	}
	check, ok := s.RepoRegistry.Get(id)
	if !ok {
		out.result.Status, out.result.Error = string(progress.Failed), strPtr(ErrCodeUnknownCheck)
		setProgress(progress.Failed)
		return out
	}
	setProgress(progress.Running)
	defer func() {
		if r := recover(); r != nil {
			log.Error("repo check panicked", "check_id", id, "panic", fmt.Sprint(r))
			out = checkOutcome{result: CheckResult{CheckID: id, Status: string(progress.Failed), Error: strPtr(ErrCodeInternal)}}
		}
		setProgress(progress.Status(out.result.Status))
	}()
	findings, err := check.RunRepo(ctx, snap)
	out.findings = findings
	if err != nil {
		code := classifyRepoCheckError(ctx, err)
		out.result.Status, out.result.Error = string(progress.Failed), strPtr(code)
		log.Info("repo check incomplete", "check_id", id, "error_code", code, "findings", len(findings), "err", err)
	}
	return out
}

func (s *Service) failRepoScan(ctx context.Context, tracker *progress.Tracker, job Job, code string, log *slog.Logger) error {
	if tracker != nil {
		for _, id := range job.Checks {
			s.setProgress(ctx, tracker, job.ScanID, id, progress.Failed, log)
		}
	}
	ev := ScanFailed{V: ProtocolVersion, Type: EventScanFailed, ScanID: job.ScanID, At: rfc3339(s.now()), Error: code}
	if err := publishEvent(ctx, s.RDB, ev); err != nil {
		return fmt.Errorf("publish scan.failed: %w", err)
	}
	return nil
}

func classifyRepoError(ctx context.Context, err error) string {
	switch {
	case errors.Is(err, repo.ErrAccess):
		return ErrCodeRepoAccessLost
	case errors.Is(err, repo.ErrEmptyRepository):
		return ErrCodeRepoEmpty
	case errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded):
		return ErrCodeTimeout
	default:
		return ErrCodeInternal
	}
}

func classifyRepoCheckError(ctx context.Context, err error) string {
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded):
		return ErrCodeTimeout
	case errors.Is(err, deps.ErrOSV):
		return ErrCodeAdvisoryDBUnavailable
	case errors.Is(err, repo.ErrTooLarge), errors.Is(err, deps.ErrTooManyAdvisories):
		return ErrCodeRepoTooLarge
	case errors.Is(err, checks.ErrManifestUnreadable):
		return ErrCodeManifestUnreadable
	default:
		return ErrCodeInternal
	}
}

// LabToken is the token the validation lab's GitHub stand-in accepts.
const LabToken = "lab-token"

// ScanLabRepo scans lab repository fullName through the lab's GitHub and OSV
// stand-ins (test_corpus/, `scanner lab`). Both endpoints must be *.lab.test
// hosts on allowed, so this can never read a real repository or ask the real
// OSV. It returns the findings and per-check results like a repo scan.
func (s *Service) ScanLabRepo(ctx context.Context, fullName string, allowed []string, osvURL string) ([]evidence.Finding, []CheckResult, error) {
	for _, raw := range []string{s.Repo.api(), osvURL} {
		u, err := url.Parse(raw)
		if err != nil || !labHostAllowed(u.Hostname(), allowed) {
			return nil, nil, ErrNotALabTarget
		}
	}
	if s.RepoRegistry == nil {
		return nil, nil, errors.New("repo checks not configured")
	}
	gh := repo.NewGitHub(s.Repo.api(), LabToken, s.Repo.Transport, s.Repo.Timeout)
	snap, err := gh.Snapshot(ctx, fullName, s.Repo.Limits)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = gh.Revoke(context.WithoutCancel(ctx)) }()
	findings, results := s.RunRepoChecks(ctx, snap, s.RepoRegistry.IDs())
	return findings, results, nil
}

func labHostAllowed(host string, allowed []string) bool {
	host = strings.ToLower(host)
	if !strings.HasSuffix(host, LabDomain) {
		return false
	}
	for _, h := range allowed {
		if strings.EqualFold(strings.TrimSpace(h), host) {
			return true
		}
	}
	return false
}
