package checks

// header_quality (ADR-0007): the quality of browser-policy headers beyond
// what security_headers (presence) and http_hardening (CSP that does not stop
// injected scripts, framing, CORS, referrer) report. Passive: the cached GET
// of the home page only.
//
//   - csp_unsafe_eval: the effective script directive allows 'unsafe-eval'
//     (Observatory deducts for it; strict-dynamic does not neutralise it).
//   - csp_base_uri_missing: a nonce-based policy (or hashes + strict-dynamic)
//     without base-uri. An injected <base> then redirects the page's relative
//     script URLs to the attacker, defeating the nonce (Google CSP Evaluator).
//   - csp_object_src_unrestricted: neither object-src nor default-src limits
//     plugins/embeds (info: no current browser runs plugins).
//   - permissions_policy_missing / coop_missing: info, best practice.
//   - cookie_response_cacheable: a response that sets a cookie explicitly
//     allows shared caches (CDN, proxy) to store it: one visitor's cookie can
//     then be served to another.
//
// Not repeated here: no CSP at all (csp_missing), 'unsafe-inline' or
// wildcard script sources (csp_ineffective), framing (clickjacking_*,
// xfo_ineffective), nosniff, referrer policy.

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
)

// HeaderQuality implements the header_quality check.
type HeaderQuality struct{}

// ID implements Check.
func (HeaderQuality) ID() string { return evidence.CheckHeaderQuality }

var ccDirectiveRe = regexp.MustCompile(`(?i)(?:^|,)\s*([a-z-]+)\s*(?:=\s*"?(\d+)"?)?`)

// Run implements Check.
func (c HeaderQuality) Run(ctx context.Context, t Target) ([]evidence.Finding, error) {
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

	if document := !resp.RedirectRefused && isHTMLDocument(resp); document {
		headerPolicies, metaPolicies := enforcedPolicies(resp.Header, resp.Body, true)
		all := append(append([]cspPolicy{}, headerPolicies...), metaPolicies...)
		payload := headerPayload(resp, "Content-Security-Policy") + metaNote(metaPolicies)
		if len(all) > 0 { // no CSP at all is security_headers' csp_missing
			if allowsEval(all) {
				add("csp_unsafe_eval", map[string]string{}, payload)
			}
			if baseURIOpen(all) {
				add("csp_base_uri_missing", map[string]string{}, payload)
			}
			if objectsOpen(all) {
				add("csp_object_src_unrestricted", map[string]string{}, payload)
			}
		}
		if strings.TrimSpace(resp.Header.Get("Permissions-Policy")) == "" {
			add("permissions_policy_missing", map[string]string{}, headerPayload(resp, "Permissions-Policy", "Feature-Policy"))
		}
		if strings.TrimSpace(resp.Header.Get("Cross-Origin-Opener-Policy")) == "" {
			add("coop_missing", map[string]string{}, headerPayload(resp, "Cross-Origin-Opener-Policy"))
		}
	}

	if name, ok := cacheableCookie(resp.Header); ok {
		out = append(out, evidence.New(c.ID(), "cookie_response_cacheable",
			map[string]string{"cookie_name": name, "cache_control": evidence.Truncate(resp.Header.Get("Cache-Control"), 200)},
			evidence.KindHttpHeader, loc+"#set-cookie="+name, headerPayload(resp, "Cache-Control", "Expires", "Vary")+
				"\nSet-Cookie: "+name+"=****"))
	}
	return out, nil
}

// scriptSources returns the effective script directive's sources of p, and
// whether one exists (script-src, else default-src).
func scriptSources(p cspPolicy) ([]string, bool) {
	if s, ok := p["script-src"]; ok {
		return s, true
	}
	s, ok := p["default-src"]
	return s, ok
}

// allowsEval: every enforced policy must allow eval for eval to be allowed
// (each policy is enforced independently).
func allowsEval(policies []cspPolicy) bool {
	for _, p := range policies {
		srcs, ok := scriptSources(p)
		if !ok {
			continue // unrestricted scripts are csp_ineffective's finding, not this one
		}
		if !contains(srcs, "'unsafe-eval'") {
			return false
		}
	}
	return anyHasScriptDirective(policies)
}

// baseURIOpen: some policy relies on script nonces (or hashes with
// 'strict-dynamic') and no policy sets base-uri. Same rule as Google's CSP
// Evaluator (checkMultipleMissingBaseUriDirective), the lab's ground truth: a
// hash-only allowlist without strict-dynamic never loads relative script URLs
// through a nonce, so a <base> gains nothing there.
func baseURIOpen(policies []cspPolicy) bool {
	needs := false
	for _, p := range policies {
		if _, ok := p["base-uri"]; ok {
			return false
		}
		srcs, _ := scriptSources(p)
		var nonce, hash, strictDynamic bool
		for _, s := range srcs {
			switch {
			case strings.HasPrefix(s, "'nonce-"):
				nonce = true
			case strings.HasPrefix(s, "'sha256-"), strings.HasPrefix(s, "'sha384-"), strings.HasPrefix(s, "'sha512-"):
				hash = true
			case s == "'strict-dynamic'":
				strictDynamic = true
			}
		}
		if nonce || (hash && strictDynamic) {
			needs = true
		}
	}
	return needs
}

// objectsOpen: no policy restricts object-src (directly, or via a
// default-src without wildcard/scheme sources).
func objectsOpen(policies []cspPolicy) bool {
	for _, p := range policies {
		srcs, ok := p["object-src"]
		if !ok {
			srcs, ok = p["default-src"]
		}
		if ok && !hasWildcardSource(srcs) {
			return false
		}
	}
	return true
}

// broadObjectSources: Observatory's DANGEROUSLY_BROAD set (mdn-http-observatory
// analyzer/tests/csp.js), the lab's ground truth for csp_object_src_unrestricted.
var broadObjectSources = map[string]bool{
	"ftp:": true, "http:": true, "https:": true, "*": true,
	"http://*": true, "http://*.*": true, "https://*": true, "https://*.*": true,
}

func hasWildcardSource(srcs []string) bool {
	for _, s := range srcs {
		if broadObjectSources[s] {
			return true
		}
	}
	return false
}

func anyHasScriptDirective(policies []cspPolicy) bool {
	for _, p := range policies {
		if _, ok := scriptSources(p); ok {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// cacheableCookie returns the first cookie set by a response whose
// Cache-Control explicitly lets shared caches store it: "public", a positive
// s-maxage, or a positive max-age, without private/no-store/no-cache.
// Responses without Cache-Control are not reported (CDNs do not cache
// Set-Cookie responses by default).
func cacheableCookie(h http.Header) (string, bool) {
	cookies := (&http.Response{Header: h}).Cookies()
	if len(cookies) == 0 {
		return "", false
	}
	cc := strings.Join(h.Values("Cache-Control"), ",")
	var public, shared, private bool
	for _, m := range ccDirectiveRe.FindAllStringSubmatch(cc, -1) {
		n, _ := strconv.Atoi(m[2])
		switch strings.ToLower(m[1]) {
		case "public":
			public = true
		case "s-maxage", "max-age":
			if n > 0 {
				shared = true
			}
		case "private", "no-store", "no-cache":
			private = true
		}
	}
	if private || (!public && !shared) {
		return "", false
	}
	return cookies[0].Name, true
}
