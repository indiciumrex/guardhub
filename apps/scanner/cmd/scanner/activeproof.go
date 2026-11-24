package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/hksolutions/guardhub/apps/scanner/internal/active"
	"github.com/hksolutions/guardhub/apps/scanner/internal/activescan"
	"github.com/hksolutions/guardhub/apps/scanner/internal/config"
	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
	"github.com/hksolutions/guardhub/apps/scanner/internal/queue"
)

// `scanner activeproof` is the founder-checkpoint proof (ADR-0008 §8.1). It
// runs ONE active check against ONE origin through the production fences
// (active.Client, activescan.Run) and writes a JSON report proving, from the
// request log:
//   - the scope guard: deliberate out-of-scope requests (another host, a
//     subdomain, the other scheme, another port, each excluded path and its
//     dot-segment, encoded, ";param", backslash and upper-case forms) are all
//     refused before the network;
//   - the kill switch: from the moment gh:active:kill or
//     gh:active:kill:<scan_id> is seen in Redis, how long until the last
//     request left (target ≤ 2 s);
//   - the rate: the shortest gap between two sent requests (1 request/s).
//
// It is not a scan service: no queue, no API, no customer target. Outside
// the lab it refuses to run unless SCANNER_ACTIVE_ENABLED=true, --confirm
// repeats the origin and ownership is proven again now with --token.
// Exit: 0 every assertion held, 3 an assertion failed, 4 ownership not
// proven, 5 killed before the start, 2 usage, 1 other failure.

const (
	proofKillTarget = 2 * time.Second
	proofMinGap     = 900 * time.Millisecond // 1 request/s, with a little clock jitter
)

type proofOptions struct {
	Origin    string
	Check     string
	ScanID    string
	Exclude   []string
	Start     []string
	KillAfter int // > 0: the proof sets gh:active:kill:<scan_id> after this many sent requests (lab)
}

type scopeProbe struct {
	URL     string `json:"url"`
	Outcome string `json:"outcome"`
}

type killProof struct {
	SeenAt        *time.Time `json:"seen_at,omitempty"` // first time a kill key was seen (or set, in the lab)
	SetByProof    bool       `json:"set_by_proof"`
	LastSentAt    *time.Time `json:"last_sent_at,omitempty"`
	SentAfterKill int        `json:"sent_after_kill"`
	StopLatencyMS int64      `json:"stop_latency_ms"` // last request sent − kill seen; 0 if none left after
	RefusedAsKill int        `json:"refused_as_killed"`
	TargetMS      int64      `json:"target_ms"`
}

type proofReport struct {
	Origin       string            `json:"origin"`
	Check        string            `json:"check"`
	ScanID       string            `json:"scan_id"`
	Ownership    string            `json:"ownership"`
	StartedAt    time.Time         `json:"started_at"`
	FinishedAt   time.Time         `json:"finished_at"`
	ScopeProbes  []scopeProbe      `json:"scope_probes"`
	Sent         int               `json:"sent"`
	Outcomes     map[string]int    `json:"outcomes"`
	MinGapMS     int64             `json:"min_gap_ms"` // shortest gap between two sent requests (-1: fewer than two)
	Kill         killProof         `json:"kill"`
	CheckError   string            `json:"check_error,omitempty"`
	Findings     int               `json:"findings"`
	Assertions   map[string]bool   `json:"assertions"`
	Failed       []string          `json:"failed_assertions"`
	PayloadsUsed []string          `json:"payloads_used"`
	RequestLog   []active.LogEntry `json:"request_log"`
}

func runActiveProof(cfg config.Config, logger *slog.Logger, args []string) int {
	fs := flag.NewFlagSet("activeproof", flag.ContinueOnError)
	origin := fs.String("origin", "", "the one origin (https://host[:port])")
	confirm := fs.String("confirm", "", "the same origin again (required outside the lab)")
	check := fs.String("check", "", "the one active check (e.g. active_xss)")
	token := fs.String("token", "", "the project's ownership token (required outside the lab)")
	scanID := fs.String("scan-id", "", "uuid of the per-scan kill key (default: random, printed)")
	exclude := fs.String("exclude", "", "comma-separated excluded path prefixes")
	start := fs.String("start", "", "comma-separated start paths on the origin")
	killAfter := fs.Int("kill-after", 0, "set the scan's kill key after N sent requests (otherwise it is set from the admin)")
	out := fs.String("out", "", "report file (default: stdout)")
	if err := fs.Parse(args); err != nil || *origin == "" || *check == "" {
		logger.Error("usage: scanner activeproof --origin URL --check ID [--confirm URL --token T] [--exclude /a,/b] [--start /p?x=1] [--scan-id UUID] [--kill-after N] [--out FILE]")
		return 2
	}
	if !evidence.ActiveChecks[*check] {
		logger.Error("not an active check", "check", *check)
		return 2
	}
	u, err := url.Parse(*origin)
	if err != nil || u.Hostname() == "" {
		logger.Error("invalid origin", "origin", *origin)
		return 2
	}
	lab := strings.HasSuffix(strings.ToLower(u.Hostname()), queue.LabDomain)
	if *scanID == "" {
		*scanID = newUUID()
	}
	logger.Info("activeproof starting", "origin", *origin, "check", *check, "scan_id", *scanID)
	ctx, stop := context.WithTimeout(context.Background(), queue.MaxActiveDeadline)
	defer stop()

	ownership := "lab"
	if !lab {
		// fail closed: the switches a real active scan needs, plus the operator repeating the origin
		if !cfg.ActiveEnabled || *confirm != *origin || *token == "" {
			logger.Error("refused: outside the lab activeproof needs SCANNER_ACTIVE_ENABLED=true, --confirm equal to --origin, and --token")
			return 2
		}
		vc := probe.New(probe.Options{Timeout: cfg.RequestTimeout, HostRPS: cfg.HostRPS, HostBurst: cfg.HostBurst, MaxRequests: 10})
		method, reason := queue.VerifyOwnershipNow(ctx, vc, *origin, *token)
		vc.Close()
		if method == "" {
			logger.Error("ownership not proven now; nothing was sent", "reason", reason)
			return 4
		}
		ownership = method
	}

	ropts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		logger.Error("invalid REDIS_URL")
		return 2
	}
	rdb := redis.NewClient(ropts)
	defer func() { _ = rdb.Close() }()

	rep, code := activeProof(ctx, rdb, proofOptions{Origin: *origin, Check: *check, ScanID: *scanID,
		Exclude: splitList(*exclude), Start: splitList(*start), KillAfter: *killAfter},
		cfg.AllowPrivateHosts, cfg.RequestTimeout, logger)
	rep.Ownership = ownership
	b, _ := json.MarshalIndent(rep, "", "  ")
	b = append(b, '\n')
	if *out == "" {
		_, _ = os.Stdout.Write(b)
	} else if err := os.WriteFile(*out, b, 0o600); err != nil {
		logger.Error("cannot write the report", "err", err)
		return 1
	}
	logger.Info("activeproof done", "scan_id", rep.ScanID, "sent", rep.Sent, "failed_assertions", rep.Failed,
		"kill_latency_ms", rep.Kill.StopLatencyMS, "min_gap_ms", rep.MinGapMS)
	return code
}

// activeProof is the proof itself (ownership is the caller's).
func activeProof(ctx context.Context, rdb redis.UniversalClient, o proofOptions, allowPrivate []string,
	timeout time.Duration, logger *slog.Logger) (proofReport, int) {
	rep := proofReport{Origin: o.Origin, Check: o.Check, ScanID: o.ScanID, StartedAt: time.Now().UTC(),
		Outcomes: map[string]int{}, Assertions: map[string]bool{}, Failed: []string{}, MinGapMS: -1}
	rep.Kill.TargetMS = proofKillTarget.Milliseconds()
	scope, err := active.NewScope(o.Origin, o.Exclude)
	if err != nil {
		logger.Error("invalid scope", "err", err)
		return rep, 2
	}
	var starts []*url.URL
	for _, p := range o.Start {
		s, err := scope.Origin().Parse(p)
		if err != nil || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
			logger.Error("start must be a path on the origin", "start", p)
			return rep, 2
		}
		starts = append(starts, s)
	}
	kill := &active.RedisKill{RDB: rdb, ScanID: o.ScanID}
	if kill.Killed(ctx) {
		logger.Error("the kill switch is set (or Redis is unreachable): nothing was sent")
		return rep, 5
	}
	reqLog := &active.RequestLog{}
	client, err := active.NewClient(active.Options{Scope: scope, Kill: kill, Log: reqLog, Limits: active.DefaultLimits(),
		AllowPrivateHosts: allowPrivate, InsecureTLS: true, Timeout: timeout})
	if err != nil {
		logger.Error("client", "err", err)
		return rep, 1
	}

	// 1. scope guard: each of these must be refused before the network
	for _, raw := range scopeProbeURLs(scope.Origin(), o.Exclude) {
		pu, err := url.Parse(raw)
		if err != nil {
			continue
		}
		_, err = client.Send(ctx, active.Baseline(o.Check, pu))
		outcome := "sent"
		switch {
		case errors.Is(err, active.ErrOutOfScope):
			outcome = active.OutcomeScope
		case err != nil:
			outcome = "error: " + err.Error()
		}
		rep.ScopeProbes = append(rep.ScopeProbes, scopeProbe{URL: raw, Outcome: outcome})
	}
	sentByScopeProbes := client.Sent()

	// 2. the kill watcher: notes when a kill key first appears (from the
	// admin), or sets the scan's key itself after N sent requests (lab)
	var mu sync.Mutex
	var seenAt *time.Time
	setByProof := false
	watchCtx, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		t := time.NewTicker(50 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-watchCtx.Done():
				return
			case <-t.C:
			}
			if o.KillAfter > 0 && client.Sent() >= o.KillAfter {
				if err := rdb.Set(watchCtx, active.ScanKillKey(o.ScanID), "1", time.Hour).Err(); err == nil {
					now := time.Now().UTC()
					mu.Lock()
					seenAt, setByProof = &now, true
					mu.Unlock()
					logger.Info("proof set the scan's kill key", "after_sent", client.Sent())
					return
				}
			}
			n, err := rdb.Exists(watchCtx, active.GlobalKillKey, active.ScanKillKey(o.ScanID)).Result()
			if err == nil && n > 0 {
				now := time.Now().UTC()
				mu.Lock()
				seenAt = &now
				mu.Unlock()
				logger.Info("kill key seen", "after_sent", client.Sent())
				return
			}
		}
	}()

	// 3. the check, through the production path
	findings, outs := activescan.Run(ctx, client, scope, []string{o.Check}, nil, nil, nil, starts)
	stopWatch()
	<-watched
	for _, oc := range outs {
		if oc.Err != nil {
			rep.CheckError = oc.Err.Error()
		}
	}
	rep.Findings = len(findings)
	rep.FinishedAt = time.Now().UTC()
	rep.RequestLog = reqLog.Entries()
	mu.Lock()
	rep.Kill.SeenAt, rep.Kill.SetByProof = seenAt, setByProof
	mu.Unlock()
	summarizeProof(&rep, sentByScopeProbes, o.KillAfter > 0)
	if len(rep.Failed) > 0 {
		return rep, 3
	}
	return rep, 0
}

// summarizeProof computes the counts and the assertions from the log.
func summarizeProof(rep *proofReport, sentByScopeProbes int, killExpected bool) {
	used := map[string]bool{}
	var last *time.Time
	var prev time.Time
	for _, e := range rep.RequestLog {
		rep.Outcomes[e.Outcome]++
		if e.Outcome == active.OutcomeKilled {
			rep.Kill.RefusedAsKill++
		}
		if e.Outcome != active.OutcomeSent && e.Outcome != active.OutcomeError {
			continue
		}
		rep.Sent++
		used[e.PayloadID] = true
		if !prev.IsZero() {
			if g := e.At.Sub(prev).Milliseconds(); rep.MinGapMS < 0 || g < rep.MinGapMS {
				rep.MinGapMS = g
			}
		}
		prev = e.At
		at := e.At
		last = &at
		if rep.Kill.SeenAt != nil && e.At.After(*rep.Kill.SeenAt) {
			rep.Kill.SentAfterKill++
		}
	}
	rep.Kill.LastSentAt = last
	if rep.Kill.SeenAt != nil && last != nil && last.After(*rep.Kill.SeenAt) {
		rep.Kill.StopLatencyMS = last.Sub(*rep.Kill.SeenAt).Milliseconds()
	}
	for id := range used {
		rep.PayloadsUsed = append(rep.PayloadsUsed, id)
	}
	sort.Strings(rep.PayloadsUsed)

	refused := len(rep.ScopeProbes) > 0 && sentByScopeProbes == 0
	for _, p := range rep.ScopeProbes {
		refused = refused && p.Outcome == active.OutcomeScope
	}
	onlyGET := true
	for _, e := range rep.RequestLog {
		onlyGET = onlyGET && e.Method == "GET"
	}
	rep.Assertions["scope_probes_all_refused_before_network"] = refused
	rep.Assertions["only_get_requests"] = onlyGET
	rep.Assertions["rate_at_most_1_per_second"] = rep.MinGapMS < 0 || rep.MinGapMS >= proofMinGap.Milliseconds()
	if killExpected {
		rep.Assertions["kill_key_set"] = rep.Kill.SeenAt != nil
	}
	if rep.Kill.SeenAt != nil {
		rep.Assertions["kill_stops_within_2s"] = rep.Kill.StopLatencyMS <= proofKillTarget.Milliseconds()
		rep.Assertions["scan_ended_killed"] = strings.Contains(rep.CheckError, active.ErrKilled.Error())
	}
	for k, ok := range rep.Assertions {
		if !ok {
			rep.Failed = append(rep.Failed, k)
		}
	}
	sort.Strings(rep.Failed)
}

// scopeProbeURLs are requests a correct scope guard must refuse.
func scopeProbeURLs(origin *url.URL, exclude []string) []string {
	host, port := origin.Hostname(), origin.Port()
	otherScheme := "http"
	if origin.Scheme == "http" {
		otherScheme = "https"
	}
	otherPort := "8443"
	if port == "8443" {
		otherPort = "9443"
	}
	o := origin.Scheme + "://" + origin.Host
	list := []string{
		"https://" + active.CanaryHost + "/",
		origin.Scheme + "://gh-scope-probe." + origin.Host + "/",
		otherScheme + "://" + origin.Host + "/",
		origin.Scheme + "://" + host + ":" + otherPort + "/",
		origin.Scheme + "://" + host + "." + active.CanaryHost + "/",
		origin.Scheme + "://gh@" + origin.Host + "/",
	}
	for _, p := range exclude {
		p = "/" + strings.Trim(p, "/")
		list = append(list,
			o+p,
			o+p+"/gh-scope-probe",
			o+"/gh-scope-probe/%2e%2e"+p,
			o+"/gh-scope-probe/.."+p,
			o+p+";gh=1",
			o+"/%5C"+strings.TrimPrefix(p, "/"),
			o+strings.ToUpper(p),
		)
	}
	return list
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
