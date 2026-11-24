// Package active is GuardHub's fenced path for active tests (ADR-0008): every
// request an active module makes goes through Client.Send, which checks, in
// order, the kill switch, the scope guard, the budgets, the rate limiter and
// the circuit breaker, and records the outcome in the request log, whether
// the request was sent or refused. Passive checks never see this package
// (checks.Target carries only probe.Client), and probe.Client stays
// GET/HEAD-only.
package active

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrOutOfScope is returned (and logged as scope_refused) for any request
// whose URL is not on the scan's exact origin, or is under an excluded path.
var ErrOutOfScope = errors.New("active: request out of scope")

// Scope is the fence of one active scan: one exact origin (scheme, host,
// port) and the path prefixes the user excluded.
type Scope struct {
	origin  *url.URL
	exclude []string
}

// NewScope builds a scope from an origin ("https://example.com[:port]", no
// path, query or credentials) and excluded path prefixes ("/admin", ...).
func NewScope(origin string, exclude []string) (Scope, error) {
	u, err := url.Parse(strings.TrimSpace(origin))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return Scope{}, fmt.Errorf("active: invalid scope origin %q", origin)
	}
	s := Scope{origin: &url.URL{Scheme: u.Scheme, Host: strings.ToLower(u.Host)}}
	for _, p := range exclude {
		p = strings.TrimSpace(p)
		if !strings.HasPrefix(p, "/") {
			return Scope{}, fmt.Errorf("active: excluded path %q must start with /", p)
		}
		s.exclude = append(s.exclude, p)
	}
	return s, nil
}

// Origin returns the scope's origin URL (a copy).
func (s Scope) Origin() *url.URL { u := *s.origin; return &u }

// Check reports whether u may be requested: same scheme, same host
// (case-insensitive, no subdomains), same effective port, no credentials,
// and not under an excluded path prefix (compared on the decoded and on the
// escaped path, so %2F tricks cannot slip past).
func (s Scope) Check(u *url.URL) error {
	if u == nil || u.User != nil || u.Opaque != "" {
		return ErrOutOfScope
	}
	if !strings.EqualFold(u.Scheme, s.origin.Scheme) || !strings.EqualFold(u.Hostname(), s.origin.Hostname()) ||
		effectivePort(u) != effectivePort(s.origin) {
		return ErrOutOfScope
	}
	for _, p := range s.exclude {
		if underPrefix(u.Path, p) || underPrefix(u.EscapedPath(), p) {
			return ErrOutOfScope
		}
	}
	return nil
}

func underPrefix(path, prefix string) bool {
	path = "/" + strings.TrimLeft(path, "/")
	lp, lpre := strings.ToLower(path), strings.ToLower(strings.TrimRight(prefix, "/"))
	return lp == lpre || strings.HasPrefix(lp, lpre+"/")
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}
