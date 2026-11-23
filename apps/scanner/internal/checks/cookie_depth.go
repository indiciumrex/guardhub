package checks

// cookie_depth (ADR-0007): cookie scoping problems beyond security_headers'
// missing Secure / HttpOnly / SameSite flags. It reads the Set-Cookie headers
// of the same cached GET of the origin root (no extra request).
//
//   - cookie_prefix_invalid: a cookie named __Secure-... without Secure, or
//     __Host-... without Secure, with a Path other than "/" or with a Domain
//     attribute. Browsers silently refuse such cookies (RFC 6265bis §4.1.3),
//     so the protection the name promises (or the session itself) is gone.
//   - cookie_domain_too_broad: a session cookie (name containing sess, sid,
//     auth, token or login; not a CSRF cookie) set with a Domain attribute
//     that the browser accepts. It is then sent to every subdomain of that
//     domain, so any subdomain (a forgotten staging host, a taken-over CNAME,
//     user content) can read it.
//
// A cookie the browser refuses because its Domain does not cover the host is
// not "too broad": it is never stored.

import (
	"context"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
)

// CookieDepth implements the cookie_depth check.
type CookieDepth struct{}

// ID implements Check.
func (CookieDepth) ID() string { return evidence.CheckCookieDepth }

// sessionCookieHints: name fragments of session identifiers (lower case).
var sessionCookieHints = []string{"sess", "sid", "auth", "token", "login"}

type setCookie struct {
	name, domain, path string
	secure, hasDomain  bool
}

// parseSetCookie reads the name and the scoping attributes of one Set-Cookie
// header (RFC 6265bis §5.6: attribute names are case-insensitive, the last
// Domain/Path wins, a leading dot of Domain is ignored).
func parseSetCookie(raw string) (setCookie, bool) {
	parts := strings.Split(raw, ";")
	name, _, ok := strings.Cut(parts[0], "=")
	name = strings.TrimSpace(name)
	if !ok || name == "" {
		return setCookie{}, false
	}
	c := setCookie{name: name}
	for _, a := range parts[1:] {
		k, v, _ := strings.Cut(a, "=")
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch k {
		case "secure":
			c.secure = true
		case "path":
			c.path = v
		case "domain":
			if d := strings.ToLower(strings.TrimPrefix(v, ".")); d != "" {
				c.domain, c.hasDomain = d, true
			}
		}
	}
	return c, true
}

// prefixProblem returns why a prefixed cookie is refused by browsers ("" if not).
func (c setCookie) prefixProblem() string {
	switch {
	case strings.HasPrefix(c.name, "__Secure-"):
		if !c.secure {
			return "secure_missing"
		}
	case strings.HasPrefix(c.name, "__Host-"):
		switch {
		case !c.secure:
			return "secure_missing"
		case c.hasDomain:
			return "domain_set"
		case c.path != "/":
			return "path_not_root"
		}
	}
	return ""
}

func isSessionCookie(name string) bool {
	n := strings.ToLower(name)
	if csrfCookieNames[n] || strings.Contains(n, "csrf") || strings.Contains(n, "xsrf") {
		return false
	}
	for _, h := range sessionCookieHints {
		if strings.Contains(n, h) {
			return true
		}
	}
	return false
}

// domainAccepted: the browser stores a cookie with this Domain for host (the
// host is the domain or under it, and the domain is not a public suffix).
func domainAccepted(domain, host string) bool {
	if domain != host && !strings.HasSuffix(host, "."+domain) {
		return false
	}
	suffix, _ := publicsuffix.PublicSuffix(domain)
	return suffix != domain
}

// Run implements Check.
func (c CookieDepth) Run(ctx context.Context, t Target) ([]evidence.Finding, error) {
	f := newFetcher(t)
	resp, err := f.get(ctx, "/")
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, f.done()
	}
	host := strings.ToLower(resp.URL.Hostname())
	var out []evidence.Finding
	seen := map[string]bool{}
	for _, raw := range resp.Header.Values("Set-Cookie") {
		ck, ok := parseSetCookie(raw)
		if !ok || seen[ck.name] {
			continue
		}
		seen[ck.name] = true
		loc := resp.URL.String() + "#set-cookie=" + ck.name
		payload := "Set-Cookie: " + maskCookie(raw)
		if why := ck.prefixProblem(); why != "" {
			out = append(out, evidence.New(c.ID(), "cookie_prefix_invalid",
				map[string]string{"cookie_name": evidence.Truncate(ck.name, 100), "reason": why},
				evidence.KindHttpHeader, loc, payload+"\nBrowsers refuse this cookie: "+prefixReasonText[why]))
			continue // a refused cookie is never stored, so its scope does not matter
		}
		if ck.hasDomain && isSessionCookie(ck.name) && domainAccepted(ck.domain, host) {
			out = append(out, evidence.New(c.ID(), "cookie_domain_too_broad",
				map[string]string{"cookie_name": evidence.Truncate(ck.name, 100), "domain": evidence.Truncate(ck.domain, 200)},
				evidence.KindHttpHeader, loc, payload+"\nWith Domain="+ck.domain+", browsers send this cookie to "+ck.domain+" and every subdomain of it."))
		}
	}
	return out, nil
}

var prefixReasonText = map[string]string{
	"secure_missing": "the __Secure-/__Host- prefix requires the Secure attribute.",
	"domain_set":     "the __Host- prefix forbids a Domain attribute.",
	"path_not_root":  "the __Host- prefix requires Path=/.",
}
