package activescan

import (
	"context"
	"errors"

	"github.com/hksolutions/guardhub/apps/scanner/internal/active"
	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
)

// ErrUnknownCheck: a requested id is not an active check.
var ErrUnknownCheck = errors.New("activescan: unknown check")

// Outcome is one requested check's result (Err nil: done).
type Outcome struct {
	CheckID string
	Err     error
}

// Run is the one active-scan path (the queue's active_scan job and the lab
// harness): discovery from the origin's "/" (as session A when given), then
// each requested check in order. A fatal stop (kill switch, breaker, budget,
// deadline) fails the running check and every later one with the same error;
// findings so far are kept.
func Run(ctx context.Context, client *active.Client, scope active.Scope, ids []string,
	sessA, sessB *active.Session, collab active.Collaborator) ([]evidence.Finding, []Outcome) {
	byID := map[string]Check{}
	for _, c := range All() {
		byID[c.ID()] = c
	}
	findings := []evidence.Finding{}
	outs := make([]Outcome, 0, len(ids))
	var stop error
	points, pages, err := DiscoverAs(ctx, client, scope.Origin(), nil, DiscoveryLimits{}, sessA)
	if err != nil {
		stop = err
	}
	env := Env{Client: client, Origin: scope.Origin(), Points: points, Pages: pages, Collab: collab,
		SessionA: sessA, SessionB: sessB}
	for _, id := range ids {
		if stop != nil {
			outs = append(outs, Outcome{id, stop})
			continue
		}
		c, ok := byID[id]
		if !ok {
			outs = append(outs, Outcome{id, ErrUnknownCheck})
			continue
		}
		fs, err := c.Run(ctx, env)
		findings = append(findings, fs...)
		if err != nil {
			stop = err
			outs = append(outs, Outcome{id, err})
			continue
		}
		outs = append(outs, Outcome{id, nil})
	}
	return findings, outs
}
