package queue

import (
	"context"
	"encoding/json"
	"time"
)

// Admin control centre (GUARDHUB_STANDARDS §8.3).
//
// CancelPrefix: the API sets gh:scan:cancel:<scan_id> when an admin cancels a
// queued or running scan; a job for that scan is then skipped (acked, nothing
// published; the API has already marked the scan cancelled and ignores later
// events). Active scans are stopped by their kill key as well (kill.go).
//
// InfoPrefix: every scanner publishes what it runs with (limits, switches) at
// gh:scanner:info:<consumer>, refreshed every InfoInterval with a TTL of
// 3 intervals, so the admin shows the effective rate limit and the scanner's
// own active-test switch instead of guessing. No secrets: no URLs, no DSNs.
const (
	CancelPrefix = "gh:scan:cancel:"
	InfoPrefix   = "gh:scanner:info:"
	InfoInterval = 30 * time.Second
)

// Info is the JSON stored under InfoPrefix+consumer.
type Info struct {
	Consumer           string  `json:"consumer"`
	Version            string  `json:"version"`
	StartedAt          string  `json:"started_at"`
	Workers            int     `json:"workers"`
	CheckConcurrency   int     `json:"check_concurrency"`
	HostRPS            float64 `json:"host_rps"`
	HostBurst          int     `json:"host_burst"`
	MaxRequestsPerScan int     `json:"max_requests_per_scan"`
	RequestTimeoutMS   int64   `json:"request_timeout_ms"`
	ActiveEnabled      bool    `json:"active_enabled"`
	ActiveOOB          bool    `json:"active_oob"` // an OOB collaborator is configured (SSRF)
	RepoScans          bool    `json:"repo_scans"`
}

// cancelled reports whether an admin cancelled scanID. A Redis error counts as
// "not cancelled": cancelling is best effort (the API ignores the scan's
// events either way); active scans have the fail-closed kill switch.
func (s *Service) cancelled(ctx context.Context, scanID string) bool {
	if s.RDB == nil || scanID == "" {
		return false
	}
	n, err := s.RDB.Exists(ctx, CancelPrefix+scanID).Result()
	return err == nil && n > 0
}

// PublishInfo keeps gh:scanner:info:<consumer> fresh until ctx ends.
func (s *Service) PublishInfo(ctx context.Context, info Info) {
	info.Consumer = s.Consumer
	b, _ := json.Marshal(info)
	key := InfoPrefix + s.Consumer
	put := func() {
		if err := s.RDB.Set(ctx, key, b, 3*InfoInterval).Err(); err != nil && ctx.Err() == nil {
			s.log().Warn("cannot publish scanner info", "err", err)
		}
	}
	put()
	t := time.NewTicker(InfoInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			put()
		}
	}
}
