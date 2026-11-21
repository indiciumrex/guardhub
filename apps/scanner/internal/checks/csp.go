package checks

// Content-Security-Policy parsing and script-policy evaluation (CSP Level 3).
// Used by security_headers (is there an enforced CSP at all, header or <meta>)
// and http_hardening (does the CSP actually stop injected scripts).

import (
	htmlstd "html"
	"net/http"
	"regexp"
	"strings"
)

// cspPolicy is one policy: directive name → source tokens (lower-cased,
// except nonce/hash values which keep their case).
type cspPolicy map[string][]string

// parseCSP parses one serialized policy. Duplicate directives: the first wins
// (CSP3 §2.2.1). Empty directives are kept (meaning "none").
func parseCSP(raw string) cspPolicy {
	p := cspPolicy{}
	for _, part := range strings.Split(raw, ";") {
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		if _, dup := p[name]; dup {
			continue
		}
		var srcs []string
		for _, f := range fields[1:] {
			lf := strings.ToLower(f)
			if strings.HasPrefix(lf, "'nonce-") || strings.HasPrefix(lf, "'sha256-") ||
				strings.HasPrefix(lf, "'sha384-") || strings.HasPrefix(lf, "'sha512-") {
				srcs = append(srcs, lf[:strings.Index(lf, "-")+1]+f[strings.Index(f, "-")+1:])
				continue
			}
			srcs = append(srcs, lf)
		}
		p[name] = srcs
	}
	return p
}

var metaCSPRe = regexp.MustCompile(`(?is)<meta\b[^>]*http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>`)
var metaContentRe = regexp.MustCompile(`(?is)\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)')`)

// enforcedPolicies returns every ENFORCED policy of a response: each
// Content-Security-Policy header value (comma-separated policies included)
// and each <meta http-equiv="Content-Security-Policy"> in an HTML body.
// Report-Only policies are not enforced and are ignored. fromMeta reports
// which came from <meta> (frame-ancestors is ignored there by browsers).
func enforcedPolicies(h http.Header, body []byte, document bool) (headerPolicies, metaPolicies []cspPolicy) {
	for _, v := range h.Values("Content-Security-Policy") {
		for _, one := range strings.Split(v, ",") {
			if strings.TrimSpace(one) != "" {
				headerPolicies = append(headerPolicies, parseCSP(one))
			}
		}
	}
	if document {
		head := body
		if len(head) > 64<<10 {
			head = head[:64<<10]
		}
		for _, tag := range metaCSPRe.FindAll(head, 8) {
			if m := metaContentRe.FindSubmatch(tag); m != nil {
				val := string(m[1]) + string(m[2])
				if strings.TrimSpace(val) != "" {
					metaPolicies = append(metaPolicies, parseCSP(htmlstd.UnescapeString(val)))
				}
			}
		}
	}
	return headerPolicies, metaPolicies
}

// scriptWeaknesses lists why one policy does NOT stop injected scripts, as
// language-neutral CSP syntax (they become a finding param shown in every
// locale); an empty list means it does. Rules (CSP3):
//   - scripts are governed by script-src, else default-src; neither = unrestricted;
//   - 'unsafe-inline' is ignored when a nonce or hash is present;
//   - with 'strict-dynamic', host and scheme sources (incl. '*', https:) are ignored;
//   - '*', http:, https: and data: let any site's (or inline data:) script run.
//
// 'unsafe-eval' alone is not reported (common in frameworks, needs a separate
// injection sink), nor is a missing object-src (browsers no longer run plugins).
func scriptWeaknesses(p cspPolicy) []string {
	srcs, ok := p["script-src"]
	directive := "script-src"
	if !ok {
		srcs, ok = p["default-src"]
		directive = "default-src"
	}
	if !ok {
		return []string{"(no script-src / default-src)"}
	}
	var nonceOrHash, strictDynamic, unsafeInline bool
	var anySite []string
	for _, s := range srcs {
		switch {
		case strings.HasPrefix(s, "'nonce-"), strings.HasPrefix(s, "'sha256-"), strings.HasPrefix(s, "'sha384-"), strings.HasPrefix(s, "'sha512-"):
			nonceOrHash = true
		case s == "'strict-dynamic'":
			strictDynamic = true
		case s == "'unsafe-inline'":
			unsafeInline = true
		case s == "*", s == "http:", s == "https:", s == "data:":
			anySite = append(anySite, s)
		}
	}
	var out []string
	if unsafeInline && !nonceOrHash {
		out = append(out, directive+" 'unsafe-inline'")
	}
	if len(anySite) > 0 && !strictDynamic {
		out = append(out, directive+" "+strings.Join(anySite, " "))
	}
	return out
}

// frameAncestors reports whether any HEADER policy sets frame-ancestors
// (browsers ignore it in <meta>).
func frameAncestors(headerPolicies []cspPolicy) bool {
	for _, p := range headerPolicies {
		if _, ok := p["frame-ancestors"]; ok {
			return true
		}
	}
	return false
}
