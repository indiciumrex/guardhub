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
	"path"
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
// and not under an excluded path prefix. The prefix is compared on every
// form a server may resolve the path to: the decoded and the escaped path,
// and the decoded path with backslashes as slashes, ";" segment parameters
// dropped and dot segments resolved, so %2F, /x/%2e%2e/admin, /admin;a=1 and
// dmin cannot slip past an excluded prefix.
func (s Scope) Check(u *url.URL) error {
	if u == nil || u.User != nil || u.Opaque != "" {
		return ErrOutOfScope
	}
	if !strings.EqualFold(u.Scheme, s.origin.Scheme) || !strings.EqualFold(u.Hostname(), s.origin.Hostname()) ||
		effectivePort(u) != effectivePort(s.origin) {
		return ErrOutOfScope
	}
	forms := []string{u.Path, u.EscapedPath(), resolvedPath(u.Path)}
	for _, p := range s.exclude {
		for _, f := range forms {
			if underPrefix(f, p) {
				return ErrOutOfScope
			}
		}
	}
	return nil
}

// resolvedPath is the path as a lenient server would serve it: backslashes
// are slashes, ";params" are dropped from each segment, dot segments resolve.
func resolvedPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		if j := strings.IndexByte(seg, ';'); j >= 0 {
			segs[i] = seg[:j]
		}
	}
	return path.Clean("/" + strings.Join(segs, "/"))
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
