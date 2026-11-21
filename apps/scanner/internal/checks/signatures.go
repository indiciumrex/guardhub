package checks

// Signature-based path probing shared by open_admin and default_creds.

import (
	"context"
	"strings"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
)

// pathProbe describes one GET and how to recognise a hit in its response.
type pathProbe struct {
	path    string
	key     string // finding key
	product string // "" when the finding key has no product param
	// group: once a probe of a group matched, later probes of the same
	// group are skipped (no request is sent). Defaults to product+key.
	group string
	// match returns a short description of the matched signature.
	match func(resp *probe.Response) (string, bool)
	// spaShell: the product is a single-page app whose shell answers EVERY
	// path, so its real page equals the soft-404 baseline. Set it only with a
	// product-specific marker: on a catch-all that carries the marker, the site
	// IS that product. (Validation lab: Grafana's default login was missed.)
	spaShell bool
}

func (p pathProbe) groupKey() string {
	if p.group != "" {
		return p.group
	}
	return p.key + "|" + p.product
}

// runProbes executes probes in order and returns findings for checkID.
func runProbes(ctx context.Context, checkID string, t Target, probes []pathProbe) ([]evidence.Finding, error) {
	f := newFetcher(t)
	base, err := f.baseline(ctx)
	if err != nil {
		return nil, err
	}
	var out []evidence.Finding
	matched := map[string]bool{}
	for _, p := range probes {
		if matched[p.groupKey()] {
			continue
		}
		resp, err := f.get(ctx, p.path)
		if err != nil {
			return out, err
		}
		if resp == nil || (len(resp.Body) == 0 && resp.StatusCode != 401) || (!p.spaShell && sameAsBaseline(resp, base)) {
			continue
		}
		sig, ok := p.match(resp)
		if !ok {
			continue
		}
		matched[p.groupKey()] = true
		params := map[string]string{"path": p.path}
		if p.product != "" {
			params["product"] = p.product
		}
		out = append(out, evidence.New(checkID, p.key, params, evidence.KindHttpResponse, t.URL(p.path), signaturePayload(resp, sig)))
	}
	return out, f.done()
}

// Matchers. All comparisons are case-insensitive unless stated.

// status200All: 200 and every needle present.
func status200All(needles ...string) func(*probe.Response) (string, bool) {
	return func(r *probe.Response) (string, bool) {
		if r.StatusCode != 200 {
			return "", false
		}
		for _, n := range needles {
			if !containsFold(r.Body, n) {
				return "", false
			}
		}
		return quoteAll(needles), true
	}
}

// all/any combinators over body needles (any status code).
func bodyAll(needles ...string) func([]byte) bool {
	return func(b []byte) bool {
		for _, n := range needles {
			if !containsFold(b, n) {
				return false
			}
		}
		return true
	}
}

func bodyAny(needles ...string) func([]byte) bool {
	return func(b []byte) bool {
		for _, n := range needles {
			if containsFold(b, n) {
				return true
			}
		}
		return false
	}
}

func bodyNone(needles ...string) func([]byte) bool {
	anyOf := bodyAny(needles...)
	return func(b []byte) bool { return !anyOf(b) }
}

// status200Where: 200 and every predicate holds; desc names the signature.
func status200Where(desc string, preds ...func([]byte) bool) func(*probe.Response) (string, bool) {
	return func(r *probe.Response) (string, bool) {
		if r.StatusCode != 200 {
			return "", false
		}
		for _, p := range preds {
			if !p(r.Body) {
				return "", false
			}
		}
		return desc, true
	}
}

func quoteAll(ss []string) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = `"` + s + `"`
	}
	return strings.Join(q, " + ")
}
