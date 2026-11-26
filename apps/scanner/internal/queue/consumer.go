package queue

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/hksolutions/guardhub/apps/scanner/internal/checks"
	"github.com/hksolutions/guardhub/apps/scanner/internal/pool"
	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
)

// Consumer defaults (docs/architecture.md §2.1).
const (
	DefaultBlock         = 5 * time.Second
	DefaultClaimMinIdle  = 10 * time.Minute
	DefaultClaimInterval = time.Minute
	DefaultMaxDeliveries = 3
)

// Service consumes gh:jobs and runs jobs on a bounded worker pool.
type Service struct {
	RDB      *redis.Client
	Consumer string
	Registry *checks.Registry
	// Repo scans (ADR-0006). RepoRegistry nil = repo scanning not configured.
	RepoRegistry *checks.RepoRegistry
	Repo         RepoScanConfig
	// Active scans (ADR-0008). The zero value refuses every active_scan job.
	Active ActiveConfig
	// NewScanProbe returns a fresh per-scan probe client (fresh budget).
	NewScanProbe func() *probe.Client
	// NewVerifyProbe returns a fresh probe client for ownership checks.
	NewVerifyProbe func() *probe.Client

	Workers          int
	CheckConcurrency int
	VerifyDeadline   time.Duration
	ShutdownTimeout  time.Duration

	Block         time.Duration
	ClaimMinIdle  time.Duration
	ClaimInterval time.Duration
	MaxDeliveries int64

	Logger *slog.Logger
	Now    func() time.Time

	// loop-goroutine state for XAUTOCLAIM
	claimCursor string
	lastClaim   time.Time
}

func (s *Service) log() *slog.Logger {
	if s.Logger == nil {
		return slog.Default()
	}
	return s.Logger
}

func (s *Service) now() time.Time {
	if s.Now == nil {
		return time.Now()
	}
	return s.Now()
}

func (s *Service) checkConcurrency() int {
	if s.CheckConcurrency < 1 {
		return 3
	}
	return s.CheckConcurrency
}

func (s *Service) verifyDeadline() time.Duration {
	if s.VerifyDeadline <= 0 {
		return 30 * time.Second
	}
	return s.VerifyDeadline
}

func orDefault[T ~int64](v, def T) T {
	if v <= 0 {
		return def
	}
	return v
}

// EnsureGroup creates the gh-scanners group (and the stream) if missing.
func (s *Service) EnsureGroup(ctx context.Context) error {
	err := s.RDB.XGroupCreateMkStream(ctx, StreamJobs, GroupScanners, "$").Err()
	if err != nil && !strings.Contains(err.Error(), "BUSYGROUP") {
		return err
	}
	return nil
}

// Run consumes jobs until ctx is cancelled, then waits up to
// ShutdownTimeout for running jobs. Jobs interrupted after that are left
// pending (not acked) so another scanner reclaims them.
func (s *Service) Run(ctx context.Context) error {
	for {
		err := s.EnsureGroup(ctx)
		if err == nil {
			break
		}
		s.log().Error("cannot create consumer group, retrying", "err", err)
		if !sleepCtx(ctx, 2*time.Second) {
			return nil
		}
	}
	s.log().Info("consumer started", "stream", StreamJobs, "group", GroupScanners, "consumer", s.Consumer, "workers", s.Workers)

	jobsCtx, cancelJobs := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelJobs()
	workers := pool.New(s.Workers)

	for ctx.Err() == nil {
		if err := workers.Acquire(ctx); err != nil {
			break
		}
		msg, claimed, err := s.next(ctx)
		if err != nil || msg == nil {
			workers.Release()
			if err != nil && ctx.Err() == nil {
				s.log().Error("reading jobs failed", "err", err)
				sleepCtx(ctx, time.Second)
			}
			continue
		}
		m := *msg
		workers.GoAcquired(func() { s.HandleMessage(jobsCtx, m, claimed) })
	}

	s.log().Info("shutting down, waiting for running jobs", "timeout", s.ShutdownTimeout.String())
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	t := time.NewTimer(orDefault(s.ShutdownTimeout, 25*time.Second))
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
		s.log().Warn("shutdown timeout reached, interrupting running jobs (they stay pending)")
		cancelJobs()
		<-done
	}
	return nil
}

// next returns the next message: first stale pending ones (XAUTOCLAIM,
// when a reclaim pass is due), then new ones (XREADGROUP ... BLOCK).
func (s *Service) next(ctx context.Context) (*redis.XMessage, bool, error) {
	if s.now().Sub(s.lastClaim) >= orDefault(s.ClaimInterval, DefaultClaimInterval) {
		if s.claimCursor == "" {
			s.claimCursor = "0-0"
		}
		msgs, cursor, err := s.RDB.XAutoClaim(ctx, &redis.XAutoClaimArgs{
			Stream:   StreamJobs,
			Group:    GroupScanners,
			Consumer: s.Consumer,
			MinIdle:  orDefault(s.ClaimMinIdle, DefaultClaimMinIdle),
			Start:    s.claimCursor,
			Count:    1,
		}).Result()
		if err != nil {
			s.lastClaim = s.now()
			s.claimCursor = "0-0"
			return nil, false, err
		}
		s.claimCursor = cursor
		if len(msgs) > 0 {
			return &msgs[0], true, nil
		}
		if cursor == "0-0" || cursor == "" {
			s.lastClaim = s.now() // full pass done
			s.claimCursor = "0-0"
		}
		if cursor != "0-0" && cursor != "" {
			return nil, false, nil // more to scan; come back immediately
		}
	}
	res, err := s.RDB.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group:    GroupScanners,
		Consumer: s.Consumer,
		Streams:  []string{StreamJobs, ">"},
		Count:    1,
		Block:    orDefault(s.Block, DefaultBlock),
	}).Result()
	if errors.Is(err, redis.Nil) || (err != nil && ctx.Err() != nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	for _, st := range res {
		if len(st.Messages) > 0 {
			return &st.Messages[0], false, nil
		}
	}
	return nil, false, nil
}

// HandleMessage processes one stream message and acks it once its result
// is published. Malformed or poison messages are logged, reported to the
// API when possible, and acked so they never loop.
func (s *Service) HandleMessage(ctx context.Context, msg redis.XMessage, claimed bool) {
	log := s.log().With("message_id", msg.ID)
	payload, _ := msg.Values[PayloadField].(string)
	job, perr := ParseJob(payload)

	if claimed && s.tooManyDeliveries(ctx, msg.ID) {
		log.Error("dropping job delivered too many times", "job_id", job.JobID, "kind", job.Kind)
		s.reportUnprocessable(ctx, job, log)
		s.ack(ctx, msg.ID, log)
		return
	}
	if perr != nil {
		log.Error("malformed job", "err", perr, "job_id", job.JobID, "kind", job.Kind)
		s.reportUnprocessable(ctx, job, log)
		s.ack(ctx, msg.ID, log)
		return
	}

	log = log.With("job_id", job.JobID, "kind", job.Kind)
	log.Info("job received", "target", job.Target, "claimed", claimed)
	if job.Kind != KindVerify && s.cancelled(ctx, job.ScanID) {
		log.Info("scan cancelled by an admin; skipped", "scan_id", job.ScanID)
		s.ack(ctx, msg.ID, log)
		return
	}
	var err error
	switch job.Kind {
	case KindScan, KindObserveScan: // observe_scan: checks already limited to observe-only (ParseJob)
		err = s.runScan(ctx, job)
	case KindVerify:
		err = s.runVerify(ctx, job)
	case KindRepoScan:
		err = s.runRepoScan(ctx, job)
	case KindActiveScan:
		err = s.runActiveScan(ctx, job)
	}
	if err != nil {
		// Not acked: it stays pending and is reclaimed after ClaimMinIdle.
		log.Warn("job not acknowledged", "err", err)
		return
	}
	s.ack(ctx, msg.ID, log)
}

// reportUnprocessable tells the API a job it is waiting for failed, when
// the payload carried enough to address the answer.
func (s *Service) reportUnprocessable(ctx context.Context, job Job, log *slog.Logger) {
	var err error
	switch {
	case (job.Kind == KindScan || job.Kind == KindObserveScan || job.Kind == KindRepoScan ||
		job.Kind == KindActiveScan) && idRe.MatchString(job.ScanID):
		err = publishEvent(ctx, s.RDB, ScanFailed{V: ProtocolVersion, Type: EventScanFailed, ScanID: job.ScanID,
			At: rfc3339(s.now()), Error: ErrCodeInternal})
	case job.Kind == KindVerify && idRe.MatchString(job.JobID) && strings.HasPrefix(job.ReplyKey, VerifyReplyPrefix) &&
		idRe.MatchString(strings.TrimPrefix(job.ReplyKey, VerifyReplyPrefix)):
		err = pushVerifyReply(ctx, s.RDB, job.ReplyKey, VerifyReply{V: ProtocolVersion, JobID: job.JobID,
			Error: strPtr(VerifyErrUnreachable)})
	}
	if err != nil {
		log.Error("could not report failed job", "err", err)
	}
}

func (s *Service) tooManyDeliveries(ctx context.Context, id string) bool {
	pending, err := s.RDB.XPendingExt(ctx, &redis.XPendingExtArgs{
		Stream: StreamJobs, Group: GroupScanners, Start: id, End: id, Count: 1,
	}).Result()
	if err != nil || len(pending) == 0 {
		return false
	}
	return pending[0].RetryCount > orDefault(s.MaxDeliveries, DefaultMaxDeliveries)
}

func (s *Service) ack(ctx context.Context, id string, log *slog.Logger) {
	if err := s.RDB.XAck(context.WithoutCancel(ctx), StreamJobs, GroupScanners, id).Err(); err != nil {
		log.Error("XACK failed", "err", err)
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
