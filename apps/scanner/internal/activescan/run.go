package activescan

import (
	"context"
	"errors"
	"net/url"

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
// harness): discovery from the origin's "/" (as session A when given) plus any
// start URLs (a route list: same-origin pages links do not reach, e.g. a
// single-page app's API; nil in production today), then
// each requested check in order. A fatal stop (kill switch, breaker, the
// scan's budget, deadline) fails the running check and every later one with
// the same error; a check that spends its own module budget fails alone and
// the next check runs. Findings so far are kept.
func Run(ctx context.Context, client *active.Client, scope active.Scope, ids []string,
	sessA, sessB *active.Session, collab active.Collaborator, start []*url.URL) ([]evidence.Finding, []Outcome) {
	byID := map[string]Check{}
	for _, c := range All() {
		byID[c.ID()] = c
	}
	findings := []evidence.Finding{}
	outs := make([]Outcome, 0, len(ids))
	var stop error
	start = withRoot(scope.Origin(), start)
	points, pages, err := DiscoverAs(ctx, client, scope.Origin(), start, DiscoveryLimits{}, sessA)
	if err != nil && IsFatal(err) { // discovery's own budget spent: the checks use what it found
		stop = err
	}
	env := Env{Client: client, Origin: scope.Origin(), Points: points, Pages: pages, Collab: collab,
		SessionA: sessA, SessionB: sessB, Start: start}
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
		if err != nil { // the check failed or ran out of its own budget: findings so far are kept
			if IsFatal(err) {
				stop = err
			}
			outs = append(outs, Outcome{id, err})
			continue
		}
		outs = append(outs, Outcome{id, nil})
	}
	return findings, outs
}

// withRoot returns the origin's "/" followed by the same-origin start URLs
// (others are dropped: the scope guard would refuse them anyway).
func withRoot(origin *url.URL, start []*url.URL) []*url.URL {
	out := []*url.URL{origin.ResolveReference(&url.URL{Path: "/"})}
	for _, u := range start {
		if u != nil && sameOrigin(origin, u) {
			out = append(out, u)
		}
	}
	return out
}
