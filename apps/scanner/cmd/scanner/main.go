// Command scanner is the GuardHub scan worker. It consumes scan and verify
// jobs from Redis (gh:jobs), runs the passive checks through the hardened
// probe client on a bounded worker pool, and publishes results (gh:events,
// progress hashes, verify replies). Configuration comes only from the
// environment (see internal/config). It stops gracefully on SIGTERM/SIGINT.
// Error-level logs and panics go to Sentry only when SENTRY_DSN_SCANNER (or SENTRY_DSN) is set
// (internal/observability); `scanner sentry-test` sends one test event.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/redis/go-redis/v9"

	"github.com/hksolutions/guardhub/apps/scanner/internal/checks"
	"github.com/hksolutions/guardhub/apps/scanner/internal/config"
	"github.com/hksolutions/guardhub/apps/scanner/internal/egressproxy"
	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/observability"
	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
	"github.com/hksolutions/guardhub/apps/scanner/internal/queue"
	"github.com/hksolutions/guardhub/apps/scanner/internal/repo"
)

func main() {
	os.Exit(run())
}

func run() int {
	// `scanner egress-proxy`: the API's CONNECT-only way out to GitHub (ADR-0006). It needs no
	// scanner configuration (no Redis): EGRESS_PROXY_LISTEN and EGRESS_PROXY_ALLOW only.
	if len(os.Args) > 1 && os.Args[1] == "egress-proxy" {
		return runEgressProxy()
	}
	cfg, err := config.Load()
	if err != nil {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("invalid configuration", "err", err)
		return 2
	}
	obs := observability.Load()
	if len(os.Args) > 1 && os.Args[1] == "sentry-test" {
		return observability.SendTestEvent(context.Background(), obs, os.Stdout, nil)
	}

	var handler slog.Handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel})
	enabled, err := observability.Init(obs)
	if err != nil {
		// A bad DSN must not stop scanning; it only disables error reporting.
		slog.New(handler).Error("error tracking disabled", "err", observability.ScrubText(err.Error()))
	}
	if enabled {
		handler = observability.NewHandler(handler, nil)
		defer observability.Flush()
		defer func() {
			if r := recover(); r != nil {
				sentry.CurrentHub().Recover(r)
				observability.Flush()
				panic(r)
			}
		}()
	}
	logger := slog.New(handler).With("service", "scanner")
	slog.SetDefault(logger)

	if len(os.Args) > 1 && os.Args[1] == "selfscan" {
		return runSelfScan(cfg, logger, os.Args[2:])
	}
	if len(os.Args) > 1 && os.Args[1] == "lab" {
		return runLab(cfg, logger, os.Args[2:])
	}

	ropts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		logger.Error("invalid REDIS_URL", "err", err)
		return 2
	}
	rdb := redis.NewClient(ropts)
	defer func() { _ = rdb.Close() }()

	if len(cfg.AllowPrivateHosts) > 0 {
		logger.Warn("private-host allowlist is active (local e2e demo only)", "hosts", cfg.AllowPrivateHosts)
	}

	// One limiter set for the whole process: the per-host rate limit holds
	// across concurrently running scans.
	limiters := probe.NewLimiters(cfg.HostRPS, cfg.HostBurst)
	base := probe.Options{
		Timeout:           cfg.RequestTimeout,
		HostRPS:           cfg.HostRPS,
		HostBurst:         cfg.HostBurst,
		MaxRequests:       cfg.MaxRequestsPerScan,
		AllowPrivateHosts: cfg.AllowPrivateHosts,
		Limiters:          limiters,
	}
	scanOpts := base
	scanOpts.InsecureSkipVerify = true // certificate problems are reported by tls_cert
	scanOpts.DNSServer = cfg.DNSServer
	// GitHub and OSV for repo scans: same IP guard, no target budget (ADR-0006).
	egress := probe.NewEgressTransport(cfg.RequestTimeout, cfg.AllowPrivateHosts)

	svc := &queue.Service{
		RDB:              rdb,
		Consumer:         cfg.ConsumerName,
		Registry:         checks.DefaultWith(checks.Options{CTURL: cfg.CTURL, OSVURL: cfg.OSVURL, OSVTransport: egress}),
		RepoRegistry:     checks.DefaultRepo(checks.RepoOptions{OSVURL: cfg.OSVURL, Transport: egress}),
		Repo:             queue.RepoScanConfig{GitHubAPI: cfg.GitHubAPIURL, Transport: egress, Timeout: 120 * time.Second, Limits: repo.DefaultLimits()},
		NewScanProbe:     func() *probe.Client { return probe.New(scanOpts) },
		NewVerifyProbe:   func() *probe.Client { return probe.New(base) },
		Workers:          cfg.Workers,
		CheckConcurrency: cfg.CheckConcurrency,
		VerifyDeadline:   cfg.VerifyDeadline,
		ShutdownTimeout:  cfg.ShutdownTimeout,
		Logger:           logger,
		Now:              time.Now,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	logger.Info("scanner starting",
		"workers", cfg.Workers, "check_concurrency", cfg.CheckConcurrency,
		"host_rps", cfg.HostRPS, "max_requests_per_scan", cfg.MaxRequestsPerScan,
		"request_timeout", cfg.RequestTimeout.String(), "checks", svc.Registry.IDs())
	if err := svc.Run(ctx); err != nil {
		logger.Error("scanner stopped with error", "err", err)
		return 1
	}
	logger.Info("scanner stopped")
	return 0
}

// runSelfScan implements `scanner selfscan <origin> <token>` (dogfooding gate).
// It prints a JSON report to stdout. Exit codes: 0 = no critical/high
// findings, 3 = critical/high findings present, 4 = ownership not verified,
// 2 = usage error, 1 = other failure.
func runSelfScan(cfg config.Config, logger *slog.Logger, args []string) int {
	if len(args) != 2 {
		logger.Error("usage: scanner selfscan <origin> <verification-token>")
		return 2
	}
	base := probe.Options{
		Timeout:           cfg.RequestTimeout,
		HostRPS:           cfg.HostRPS,
		HostBurst:         cfg.HostBurst,
		MaxRequests:       cfg.MaxRequestsPerScan,
		AllowPrivateHosts: cfg.AllowPrivateHosts,
		Limiters:          probe.NewLimiters(cfg.HostRPS, cfg.HostBurst),
	}
	scanOpts := base
	scanOpts.InsecureSkipVerify = true // certificate problems are reported by tls_cert
	scanOpts.DNSServer = cfg.DNSServer
	svc := &queue.Service{
		Registry:       checks.DefaultWith(checks.Options{CTURL: cfg.CTURL, OSVURL: cfg.OSVURL, OSVTransport: probe.NewEgressTransport(cfg.RequestTimeout, cfg.AllowPrivateHosts)}),
		NewScanProbe:   func() *probe.Client { return probe.New(scanOpts) },
		NewVerifyProbe: func() *probe.Client { return probe.New(base) },
		VerifyDeadline: cfg.VerifyDeadline,
		Logger:         logger,
		Now:            time.Now,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	report, err := svc.SelfScan(ctx, args[0], args[1])
	if errors.Is(err, queue.ErrNotVerified) {
		logger.Error("ownership not verified; nothing was scanned", "err", err)
		return 4
	}
	if err != nil {
		logger.Error("self-scan failed", "err", err)
		return 1
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return 1
	}
	for _, f := range report.Findings {
		if f.Severity == evidence.SeverityCritical || f.Severity == evidence.SeverityHigh {
			return 3
		}
	}
	return 0
}

// runEgressProxy serves the CONNECT-only egress proxy until SIGTERM.
func runEgressProxy() int {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "egress-proxy")
	allow := os.Getenv("EGRESS_PROXY_ALLOW")
	listen := os.Getenv("EGRESS_PROXY_LISTEN")
	if listen == "" {
		listen = ":8888"
	}
	if strings.TrimSpace(allow) == "" {
		logger.Error("EGRESS_PROXY_ALLOW is empty: refusing to start an open proxy")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	p := egressproxy.New(allow, probe.GuardedDialer(10*time.Second, nil), logger)
	logger.Info("egress proxy starting", "listen", listen, "allow", allow)
	if err := egressproxy.Serve(ctx, listen, p); err != nil {
		logger.Error("egress proxy stopped with error", "err", err)
		return 1
	}
	return 0
}
