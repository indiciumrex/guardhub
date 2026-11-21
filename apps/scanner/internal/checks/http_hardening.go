package checks

// http_hardening: how well the site's browser-facing policies hold up, beyond
// whether the headers exist (security_headers). Passive: the cached GET of the
// home page, plus at most two GETs of the home page with an Origin header
// (exactly what any browser sends for a cross-origin request). It never sends
// cookies, never sends PUT/DELETE/TRACE, and never submits anything.
//
// Deliberately NOT checked: which HTTP methods are "allowed". Proving that
// PUT/DELETE work means sending them (§9.2), and an Allow header alone is not
// reliable (frameworks advertise generically; single-page apps answer 200 to
// everything). See docs/checks/http_hardening.md.

import (
	"context"
	"strings"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
)

// HTTPHardening implements the http_hardening check.
type HTTPHardening struct{}

// ID implements Check.
func (HTTPHardening) ID() string { return evidence.CheckHttpHardening }

// corsProbeOrigin is an origin no site can legitimately trust: the reserved
// .invalid TLD (RFC 2606) never resolves.
const corsProbeOrigin = "https://guardhub-cors-check.invalid"

// Run implements Check.
func (c HTTPHardening) Run(ctx context.Context, t Target) ([]evidence.Finding, error) {
	f := newFetcher(t)
	resp, err := f.get(ctx, "/")
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, f.done()
	}
	var out []evidence.Finding
	loc := resp.URL.String()
	add := func(key string, params map[string]string, payload string) {
		out = append(out, evidence.New(c.ID(), key, params, evidence.KindHttpHeader, loc, payload))
	}

	document := !resp.RedirectRefused && isHTMLDocument(resp)
	if document {
		headerPolicies, metaPolicies := enforcedPolicies(resp.Header, resp.Body, true)
		all := append(append([]cspPolicy{}, headerPolicies...), metaPolicies...)
		if len(all) > 0 { // no CSP at all is security_headers' csp_missing
			if reasons := weakestReasons(all); len(reasons) > 0 {
				add("csp_ineffective", map[string]string{"reasons": strings.Join(reasons, "; ")},
					headerPayload(resp, "Content-Security-Policy")+metaNote(metaPolicies))
			}
		}
		if v, bad := ineffectiveXFO(resp, headerPolicies); bad {
			add("xfo_ineffective", map[string]string{"value": v}, headerPayload(resp, "X-Frame-Options", "Content-Security-Policy"))
		}
		if unsafeURLReferrer(resp.Header.Values("Referrer-Policy")) {
			add("referrer_policy_unsafe_url", map[string]string{}, headerPayload(resp, "Referrer-Policy"))
		}
	}

	// CORS: does the home page let ANY site read it with the visitor's cookies?
	cors, err := t.Probe.GetWithOrigin(ctx, t.URL("/"), corsProbeOrigin)
	if err != nil {
		if isFatal(ctx, err) {
			return out, err
		}
		return out, nil
	}
	if allowsWithCredentials(cors, corsProbeOrigin) {
		out = append(out, evidence.New(c.ID(), "cors_any_origin_with_credentials", map[string]string{"origin": corsProbeOrigin},
			evidence.KindHttpHeader, cors.URL.String(), corsPayload(cors, corsProbeOrigin)))
		return out, nil // reflecting any origin includes "null": one finding
	}
	nullResp, err := t.Probe.GetWithOrigin(ctx, t.URL("/"), "null")
	if err != nil {
		if isFatal(ctx, err) {
			return out, err
		}
		return out, nil
	}
	if allowsWithCredentials(nullResp, "null") {
		out = append(out, evidence.New(c.ID(), "cors_null_origin_with_credentials", map[string]string{},
			evidence.KindHttpHeader, nullResp.URL.String(), corsPayload(nullResp, "null")))
	}
	return out, nil
}

// weakestReasons: every enforced policy applies, so scripts are stopped if ANY
// one of them stops them. Report only when all of them are weak (the first
// policy's reasons).
func weakestReasons(policies []cspPolicy) []string {
	var first []string
	for i, p := range policies {
		r := scriptWeaknesses(p)
		if len(r) == 0 {
			return nil
		}
		if i == 0 {
			first = r
		}
	}
	return first
}

func metaNote(meta []cspPolicy) string {
	if len(meta) == 0 {
		return ""
	}
	return "\n(plus a policy in <meta http-equiv=\"Content-Security-Policy\">)"
}

// ineffectiveXFO: X-Frame-Options is present but not DENY/SAMEORIGIN (e.g. the
// obsolete ALLOW-FROM, which browsers ignore), and no header CSP sets
// frame-ancestors, so the page can be framed. A missing XFO is
// security_headers' clickjacking_unprotected.
func ineffectiveXFO(resp *probe.Response, headerPolicies []cspPolicy) (string, bool) {
	vals := resp.Header.Values("X-Frame-Options")
	if len(vals) == 0 || frameAncestors(headerPolicies) {
		return "", false
	}
	v := strings.TrimSpace(strings.Join(vals, ", "))
	switch strings.ToUpper(v) {
	case "DENY", "SAMEORIGIN":
		return "", false
	}
	return evidence.Truncate(v, 120), true
}

// unsafeURLReferrer: browsers use the LAST policy token they recognise.
func unsafeURLReferrer(values []string) bool {
	known := map[string]bool{"no-referrer": true, "no-referrer-when-downgrade": true, "origin": true,
		"origin-when-cross-origin": true, "same-origin": true, "strict-origin": true,
		"strict-origin-when-cross-origin": true, "unsafe-url": true}
	last := ""
	for _, v := range values {
		for _, tok := range strings.Split(v, ",") {
			tok = strings.ToLower(strings.TrimSpace(tok))
			if known[tok] {
				last = tok
			}
		}
	}
	return last == "unsafe-url"
}

// allowsWithCredentials: the response lets origin read it WITH the visitor's
// cookies (Access-Control-Allow-Origin echoes origin and
// Access-Control-Allow-Credentials is true). "*" never counts: browsers refuse
// credentials with a wildcard.
func allowsWithCredentials(resp *probe.Response, origin string) bool {
	acao := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin"))
	acac := strings.EqualFold(strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials")), "true")
	return acac && strings.EqualFold(acao, origin)
}

func corsPayload(resp *probe.Response, origin string) string {
	return "Request header: Origin: " + origin + "\n" +
		headerPayload(resp, "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Vary")
}
