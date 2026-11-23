package checks

import (
	"net/http"
	"testing"
)

func cookieSite(t *testing.T, cookies ...string) string {
	t.Helper()
	return site(t, false, map[string]http.HandlerFunc{"/": func(w http.ResponseWriter, _ *http.Request) {
		for _, c := range cookies {
			w.Header().Add("Set-Cookie", c)
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!doctype html><title>x</title>"))
	}}).URL
}

func TestCookieDepthPrefixes(t *testing.T) {
	cases := []struct {
		cookie, reason string
	}{
		{"__Host-sid=a; Path=/; Secure; HttpOnly", ""},
		{"__Host-sid=a; Path=/app; Secure", "path_not_root"},
		{"__Host-sid=a; Secure", "path_not_root"},
		{"__Host-sid=a; Path=/; Secure; Domain=127.0.0.1", "domain_set"},
		{"__Host-sid=a; Path=/", "secure_missing"},
		{"__Secure-t=a; Path=/", "secure_missing"},
		{"__Secure-t=a; path=/x; SECURE", ""},
		{"__host-sid=a; Path=/app", ""}, // the prefix is case-sensitive (RFC 6265bis, tough-cookie 5)
	}
	for _, tc := range cases {
		fs := run(t, CookieDepth{}, cookieSite(t, tc.cookie))
		if tc.reason == "" {
			requireKeys(t, fs)
			continue
		}
		requireKeys(t, fs, "cookie_prefix_invalid")
		if got := findKey(t, fs, "cookie_prefix_invalid").Params["reason"]; got != tc.reason {
			t.Errorf("%q: reason %q, want %q", tc.cookie, got, tc.reason)
		}
	}
}

func TestCookieDepthDomainScope(t *testing.T) {
	cases := []struct {
		host, cookie string
		want         bool
	}{
		{"app.example.com", "sid=a; Domain=example.com; Secure; HttpOnly", true},
		{"app.example.com", "connect.sid=a; Domain=.app.example.com; Secure", true}, // the host itself + its subdomains
		{"app.example.com", "PHPSESSID=a; Path=/; Secure", false},                   // host-only
		{"app.example.com", "_ga=GA1.1.1; Domain=example.com", false},               // not a session cookie
		{"app.example.com", "csrftoken=x; Domain=example.com", false},               // CSRF cookie, not a session
		{"app.example.com", "sid=a; Domain=other.com", false},                       // refused by the browser
		{"app.example.co.uk", "sid=a; Domain=co.uk", false},                         // public suffix: refused
	}
	for _, tc := range cases {
		ck, ok := parseSetCookie(tc.cookie)
		if !ok {
			t.Fatalf("parse %q", tc.cookie)
		}
		got := ck.prefixProblem() == "" && ck.hasDomain && isSessionCookie(ck.name) && domainAccepted(ck.domain, tc.host)
		if got != tc.want {
			t.Errorf("%s %q: broad=%v, want %v", tc.host, tc.cookie, got, tc.want)
		}
	}
	// end to end: the test server is an IP address, which has no subdomains, so a
	// Domain attribute equal to it does not widen the cookie's scope
	requireKeys(t, run(t, CookieDepth{}, cookieSite(t, "session=a; Domain=127.0.0.1; Secure; HttpOnly")))
}

func TestCookieDepthNoCookies(t *testing.T) {
	requireKeys(t, run(t, CookieDepth{}, cookieSite(t)))
}
