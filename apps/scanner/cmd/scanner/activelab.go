package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/hksolutions/guardhub/apps/scanner/internal/accuracy"
	"github.com/hksolutions/guardhub/apps/scanner/internal/active"
	"github.com/hksolutions/guardhub/apps/scanner/internal/activescan"
	"github.com/hksolutions/guardhub/apps/scanner/internal/config"
	"github.com/hksolutions/guardhub/apps/scanner/internal/queue"
)

// runActiveLab implements `scanner activelab` (ADR-0008 §9, Gate M): the
// production active path (activescan.Run: discovery from "/" plus the
// manifest's start paths, every fence)
// against the lab's active manifests, scored like `scanner lab`. Only
// *.lab.test origins are accepted. Exit: 0 scored, 1 failure, 2 usage.
func runActiveLab(cfg config.Config, logger *slog.Logger, args []string) int {
	fs := flag.NewFlagSet("activelab", flag.ContinueOnError)
	manifests := fs.String("manifests", "", "directory with the active manifests (*.yaml, active: true)")
	out := fs.String("out", "", "directory for the scorecards")
	results := fs.String("results", "", "optional: raw findings + request logs per target (JSON)")
	source := fs.String("source", "unknown", "git revision (recorded in the scorecard)")
	rps := fs.Float64("rps", 1, "requests per second per target (production: 1)")
	oob := fs.String("oob", "", "optional: the lab OOB collaborator base URL (SSRF)")
	if err := fs.Parse(args); err != nil || *manifests == "" || *out == "" {
		logger.Error("usage: scanner activelab --manifests DIR --out DIR [--results FILE] [--source REV] [--rps N] [--oob URL]")
		return 2
	}
	ms, err := accuracy.LoadManifests(*manifests)
	if err != nil {
		logger.Error("invalid manifests", "err", err)
		return 1
	}
	var collab active.Collaborator
	if *oob != "" {
		collab = active.HTTPCollaborator{Base: strings.TrimRight(*oob, "/"), HTTP: labHTTPClient(cfg)}
	}
	type targetResult struct {
		accuracy.TargetRun
		Log []active.LogEntry `json:"request_log"`
	}
	var runs []accuracy.TargetRun
	var raw []targetResult
	for _, m := range ms {
		if !m.Active {
			logger.Error("not an active manifest", "target", m.Target)
			return 1
		}
		u, err := url.Parse(m.Origin)
		if err != nil || !strings.HasSuffix(strings.ToLower(u.Hostname()), queue.LabDomain) {
			logger.Error("refusing a non-lab target", "target", m.Target, "origin", m.Origin)
			return 1
		}
		sessA, sessB, err := loadLabSessions(*manifests, m.Sessions)
		if err != nil {
			logger.Error("cannot read lab sessions", "target", m.Target, "err", err)
			return 1
		}
		scope, err := active.NewScope(m.Origin, m.Exclude)
		if err != nil {
			logger.Error("bad origin", "target", m.Target, "err", err)
			return 1
		}
		lim := active.DefaultLimits()
		lim.RPS = *rps
		reqLog := &active.RequestLog{}
		client, err := active.NewClient(active.Options{Scope: scope, Kill: &active.StaticKill{}, Log: reqLog, Limits: lim,
			AllowPrivateHosts: cfg.AllowPrivateHosts, InsecureTLS: true, Timeout: cfg.RequestTimeout})
		if err != nil {
			logger.Error("client", "err", err)
			return 1
		}
		ctx, cancel := context.WithTimeout(context.Background(), queue.MaxActiveDeadline)
		var start []*url.URL
		for _, p := range m.Start {
			s, err := u.Parse(p)
			if err != nil || !strings.HasPrefix(p, "/") || s.Host != u.Host {
				cancel()
				logger.Error("start must be a path on the origin", "target", m.Target, "start", p)
				return 1
			}
			start = append(start, s)
		}
		findings, outs := activescan.Run(ctx, client, scope, m.Checks, sessA, sessB, collab, start)
		cancel()
		run := accuracy.TargetRun{Target: m.Target, Origin: m.Origin, Findings: findings, Failed: map[string]string{},
			Requests: map[string]int{}}
		for _, o := range outs {
			if o.Err != nil {
				run.Failed[o.CheckID] = o.Err.Error()
			}
		}
		for _, e := range reqLog.Entries() {
			if e.Outcome == active.OutcomeSent {
				run.Requests[e.Module]++
			}
		}
		logger.Info("active lab target scanned", "target", m.Target, "findings", len(findings),
			"failed_checks", len(run.Failed), "requests", client.Sent())
		runs = append(runs, run)
		raw = append(raw, targetResult{run, reqLog.Entries()})
	}
	if *results != "" {
		b, err := json.MarshalIndent(raw, "", "  ")
		if err == nil {
			err = os.WriteFile(*results, append(b, '\n'), 0o644) //nolint:gosec // lab output
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
	for _, c := range sc.Checks {
		fmt.Printf("%-16s tp=%-3d fp=%-3d fn=%-3d errors=%d gate=%v\n", c.CheckID, c.TP, c.FP, c.FN, c.Errors, c.MeetsGate)
	}
	return 0
}

// loadLabSessions reads the lab-made session file (none: anonymous scan).
func loadLabSessions(dir, name string) (*active.Session, *active.Session, error) {
	if name == "" {
		return nil, nil, nil
	}
	if strings.Contains(name, "..") || filepath.IsAbs(name) {
		return nil, nil, fmt.Errorf("sessions must be a file name under the manifests directory: %q", name)
	}
	b, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // lab-made file under the manifests directory
	if err != nil {
		return nil, nil, err
	}
	var s struct {
		A *active.Session `json:"a"`
		B *active.Session `json:"b"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, nil, err
	}
	for _, x := range []*active.Session{s.A, s.B} {
		if x != nil {
			if err := x.Validate(); err != nil {
				return nil, nil, err
			}
		}
	}
	return s.A, s.B, nil
}
