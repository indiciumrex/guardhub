package queue

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/hksolutions/guardhub/apps/scanner/internal/checks"
	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/pool"
	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
	"github.com/hksolutions/guardhub/apps/scanner/internal/progress"
)

// errShutdown means the job was interrupted by shutdown: nothing is
// published and the message stays pending so another scanner reclaims it.
var errShutdown = errors.New("interrupted by shutdown")

type checkOutcome struct {
	findings []evidence.Finding
	result   CheckResult
}

// runScan executes a scan job end to end and publishes its events. A
// non-nil error means the result could not be published (or the scanner is
// shutting down) and the job must not be acked.
func (s *Service) runScan(jobCtx context.Context, job Job) error {
	log := s.log().With("job_id", job.JobID, "scan_id", job.ScanID, "target", job.Target)
	if err := publishEvent(jobCtx, s.RDB, ScanStarted{V: ProtocolVersion, Type: EventScanStarted, ScanID: job.ScanID, At: rfc3339(s.now())}); err != nil {
		return fmt.Errorf("publish scan.started: %w", err)
	}
	tracker := progress.NewTracker(s.RDB)
	if err := tracker.Init(jobCtx, job.ScanID, job.Checks); err != nil {
		log.Warn("progress init failed", "err", err)
	}

	scanCtx, cancel := context.WithTimeout(jobCtx, job.Deadline())
	defer cancel()

	client := s.NewScanProbe()
	defer client.Close()
	target, err := checks.NewTarget(job.Target, client)
	if err != nil { // already validated by ParseJob; defensive
		return s.failScan(jobCtx, tracker, job, ErrCodeInternal, log)
	}

	if err := preflight(scanCtx, target); err != nil {
		if jobCtx.Err() != nil {
			return errShutdown
		}
		code := classifyScanError(scanCtx, err)
		log.Info("scan cannot run", "error_code", code, "err", err)
		return s.failScan(jobCtx, tracker, job, code, log)
	}

	outcomes := make([]checkOutcome, len(job.Checks))
	for i, id := range job.Checks {
		// Default for checks that never start because the deadline passed.
		outcomes[i] = checkOutcome{result: CheckResult{CheckID: id, Status: string(progress.Failed), Error: strPtr(ErrCodeTimeout)}}
	}
	pool.ForEach(scanCtx, s.checkConcurrency(), len(job.Checks), func(ctx context.Context, i int) {
		outcomes[i] = s.runCheck(ctx, jobCtx, tracker, job, job.Checks[i], target, log)
	})
	if jobCtx.Err() != nil {
		return errShutdown
	}

	findings := []evidence.Finding{}
	results := make([]CheckResult, 0, len(outcomes))
	for i, o := range outcomes {
		findings = append(findings, o.findings...)
		results = append(results, o.result)
		if o.result.Status == string(progress.Failed) && o.result.Error != nil && *o.result.Error == ErrCodeTimeout {
			s.setProgress(jobCtx, tracker, job.ScanID, job.Checks[i], progress.Failed, log)
		}
	}
	ev := ScanCompleted{V: ProtocolVersion, Type: EventScanCompleted, ScanID: job.ScanID, At: rfc3339(s.now()),
		Findings: findings, CheckResults: results}
	if err := publishEvent(jobCtx, s.RDB, ev); err != nil {
		return fmt.Errorf("publish scan.completed: %w", err)
	}
	log.Info("scan completed", "findings", len(findings), "requests", client.RequestsUsed())
	return nil
}

// preflight refuses non-public targets before any check runs and makes sure
// the origin answers at all. The root GET is cached for the checks.
func preflight(ctx context.Context, t checks.Target) error {
	if err := t.Probe.CheckHost(ctx, t.Host()); err != nil {
		return err
	}
	_, err := t.Probe.Get(ctx, t.URL("/"))
	return err
}

func (s *Service) failScan(ctx context.Context, tracker *progress.Tracker, job Job, code string, log *slog.Logger) error {
	for _, id := range job.Checks {
		s.setProgress(ctx, tracker, job.ScanID, id, progress.Failed, log)
	}
	ev := ScanFailed{V: ProtocolVersion, Type: EventScanFailed, ScanID: job.ScanID, At: rfc3339(s.now()), Error: code}
	if err := publishEvent(ctx, s.RDB, ev); err != nil {
		return fmt.Errorf("publish scan.failed: %w", err)
	}
	return nil
}

func (s *Service) runCheck(ctx, jobCtx context.Context, tracker *progress.Tracker, job Job, id string, target checks.Target, log *slog.Logger) (out checkOutcome) {
	out.result = CheckResult{CheckID: id, Status: string(progress.Done)}
	check, ok := s.Registry.Get(id)
	if !ok {
		out.result.Status, out.result.Error = string(progress.Failed), strPtr(ErrCodeUnknownCheck)
		s.setProgress(jobCtx, tracker, job.ScanID, id, progress.Failed, log)
		return out
	}
	s.setProgress(jobCtx, tracker, job.ScanID, id, progress.Running, log)
	defer func() {
		if r := recover(); r != nil {
			log.Error("check panicked", "check_id", id, "panic", fmt.Sprint(r))
			out = checkOutcome{result: CheckResult{CheckID: id, Status: string(progress.Failed), Error: strPtr(ErrCodeInternal)}}
		}
		s.setProgress(jobCtx, tracker, job.ScanID, id, progress.Status(out.result.Status), log)
	}()
	findings, err := check.Run(ctx, target)
	out.findings = findings
	if err != nil {
		code := classifyCheckError(ctx, err)
		out.result.Status, out.result.Error = string(progress.Failed), strPtr(code)
		log.Info("check failed", "check_id", id, "error_code", code, "err", err)
	}
	return out
}

func (s *Service) setProgress(ctx context.Context, t *progress.Tracker, scanID, checkID string, st progress.Status, log *slog.Logger) {
	if err := t.Set(ctx, scanID, checkID, st); err != nil {
		log.Warn("progress update failed", "check_id", checkID, "err", err)
	}
}

// classifyScanError maps a preflight error to a scan.failed code.
func classifyScanError(ctx context.Context, err error) string {
	switch {
	case errors.Is(err, probe.ErrBlockedAddress):
		return ErrCodeTargetBlocked
	case errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded):
		return ErrCodeTimeout
	case errors.Is(err, probe.ErrUnresolvableTarget), errors.Is(err, probe.ErrTooManyRedirects), isNetError(err):
		return ErrCodeTargetUnreachable
	default:
		return ErrCodeInternal
	}
}

// classifyCheckError maps a check error to a check_results error code.
func classifyCheckError(ctx context.Context, err error) string {
	switch {
	case errors.Is(err, probe.ErrBudgetExceeded):
		return ErrCodeBudgetExceeded
	case errors.Is(err, checks.ErrTargetUnreachable):
		return ErrCodeTargetUnreachable
	default:
		return classifyScanError(ctx, err)
	}
}

func isNetError(err error) bool {
	var ne net.Error
	var op *net.OpError
	return errors.As(err, &ne) || errors.As(err, &op)
}
