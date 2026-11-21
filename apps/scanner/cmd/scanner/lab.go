package main

// `scanner lab`: the validation lab runner (test_corpus/, docs/accuracy/).
// It scans every lab target named by the manifests with the production
// checks, probe client and budget, then scores the findings against the
// manifests' ground truth and writes the accuracy scorecards. Lab targets
// must be *.lab.test hosts on SCANNER_ALLOW_PRIVATE_HOSTS
// (queue.ScanLabOrigin refuses anything else), so this cannot scan a real site.

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/hksolutions/guardhub/apps/scanner/internal/accuracy"
	"github.com/hksolutions/guardhub/apps/scanner/internal/checks"
	"github.com/hksolutions/guardhub/apps/scanner/internal/config"
	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
	"github.com/hksolutions/guardhub/apps/scanner/internal/queue"
)

// runLab exit codes: 0 = scored (whatever the scores are), 1 = failure, 2 = usage.
func runLab(cfg config.Config, logger *slog.Logger, args []string) int {
	fs := flag.NewFlagSet("lab", flag.ContinueOnError)
	manifests := fs.String("manifests", "", "directory with the target manifests (*.yaml)")
	out := fs.String("out", "", "directory for scorecard.json, README.md and <check_id>.md")
	results := fs.String("results", "", "optional: also write the raw findings per target (JSON)")
	rootsFile := fs.String("roots", "", "optional: PEM file with the lab CA (certificate verification)")
	source := fs.String("source", "unknown", "git revision the lab runs on (recorded in the scorecard)")
	recursionProbe := fs.String("dns-recursion-probe", "", "out-of-zone name for the open-resolver test (the lab has no internet)")
	shared := fs.String("shared", "", "optional: also write the API's gate file (packages/shared/accuracy.json)")
	if err := fs.Parse(args); err != nil || *manifests == "" || *out == "" {
		logger.Error("usage: scanner lab --manifests DIR --out DIR [--results FILE] [--roots PEM] [--source REV] [--shared FILE]")
		return 2
	}
	ms, err := accuracy.LoadManifests(*manifests)
	if err != nil {
		logger.Error("invalid manifests", "err", err)
		return 1
	}
	opts := checks.Options{DNSRecursionProbe: *recursionProbe, CTURL: cfg.CTURL}
	if *rootsFile != "" {
		pem, err := os.ReadFile(*rootsFile)
		if err != nil {
			logger.Error("cannot read lab roots", "err", err)
			return 1
		}
		opts.Roots = x509.NewCertPool()
		if !opts.Roots.AppendCertsFromPEM(pem) {
			logger.Error("no certificate in lab roots file")
			return 1
		}
	}

	scanOpts := probe.Options{
		Timeout:            cfg.RequestTimeout,
		HostRPS:            cfg.HostRPS,
		HostBurst:          cfg.HostBurst,
		MaxRequests:        cfg.MaxRequestsPerScan,
		AllowPrivateHosts:  cfg.AllowPrivateHosts,
		Limiters:           probe.NewLimiters(cfg.HostRPS, cfg.HostBurst),
		InsecureSkipVerify: true, // same as production scans: tls_cert reports certificate problems
		DNSServer:          cfg.DNSServer,
	}
	svc := &queue.Service{
		Registry:     checks.DefaultWith(opts),
		NewScanProbe: func() *probe.Client { return probe.New(scanOpts) },
		Logger:       logger,
		Now:          time.Now,
	}

	var runs []accuracy.TargetRun
	for _, m := range ms {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		findings, checkResults, cost, err := svc.ScanLabOrigin(ctx, m.Origin, cfg.AllowPrivateHosts)
		cancel()
		run := accuracy.TargetRun{Target: m.Target, Origin: m.Origin, Findings: findings, Failed: map[string]string{}, Requests: cost}
		if errors.Is(err, queue.ErrNotALabTarget) {
			logger.Error("refusing a non-lab target", "target", m.Target, "origin", m.Origin)
			return 1
		}
		if err != nil {
			run.Error = err.Error()
		}
		for _, r := range checkResults {
			if r.Status != "done" {
				code := "failed"
				if r.Error != nil {
					code = *r.Error
				}
				run.Failed[r.CheckID] = code
			}
		}
		logger.Info("lab target scanned", "target", m.Target, "findings", len(findings), "failed_checks", len(run.Failed), "error", run.Error)
		runs = append(runs, run)
	}

	if *results != "" {
		raw, err := json.MarshalIndent(runs, "", "  ")
		if err == nil {
			err = os.WriteFile(*results, append(raw, '\n'), 0o644) //nolint:gosec // lab output
		}
		if err != nil {
			logger.Error("cannot write results", "err", err)
			return 1
		}
	}
	sc := accuracy.NewScorecard(*source, ms, accuracy.Score(ms, runs))
	if err := accuracy.Write(*out, sc); err != nil {
		logger.Error("cannot write scorecards", "err", err)
		return 1
	}
	if *shared != "" {
		if err := accuracy.WriteShared(*shared, sc); err != nil {
			logger.Error("cannot write the shared gate file", "err", err)
			return 1
		}
	}
	for _, c := range sc.Checks {
		fmt.Printf("%-20s tp=%-3d fp=%-3d fn=%-3d errors=%d gate=%v\n", c.CheckID, c.TP, c.FP, c.FN, c.Errors, c.MeetsGate)
	}
	return 0
}
