package checks

// security_headers: inspects the response headers of one GET of the origin
// root (following same-host redirects): CSP, HSTS (https only),
// X-Content-Type-Options, clickjacking protection and cookie flags.

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
)

// SecurityHeaders implements the security_headers check.
type SecurityHeaders struct{}

// ID implements Check.
func (SecurityHeaders) ID() string { return evidence.CheckSecurityHeaders }

// hstsMinMaxAge is 180 days, the commonly recommended minimum.
const hstsMinMaxAge = 15552000

var (
	maxAgeRe         = regexp.MustCompile(`(?i)(?:^|;)\s*max-age\s*=\s*"?(\d+)"?`)
	frameAncestorsRe = regexp.MustCompile(`(?i)(?:^|;)\s*frame-ancestors\s`)
)

// Run implements Check.
func (c SecurityHeaders) Run(ctx context.Context, t Target) ([]evidence.Finding, error) {
	f := newFetcher(t)
	resp, err := f.get(ctx, "/")
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, f.done()
	}
	loc := resp.URL.String()
	h := resp.Header
	var out []evidence.Finding
	add := func(key string, params map[string]string, location string, headers ...string) {
		out = append(out, evidence.New(c.ID(), key, params, evidence.KindHttpHeader, location, headerPayload(resp, headers...)))
	}
	allHeaders := []string{"Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options"}

	// A redirect to another host (e.g. example.com -> www.example.com) is
	// not a document: only HSTS and cookies are meaningful on it.
	document := !resp.RedirectRefused

	csp := strings.Join(h.Values("Content-Security-Policy"), "; ")
	if document && strings.TrimSpace(csp) == "" {
		add("csp_missing", map[string]string{}, loc, allHeaders...)
	}

	if resp.URL.Scheme == "https" {
		hsts := h.Get("Strict-Transport-Security")
		if strings.TrimSpace(hsts) == "" {
			add("hsts_missing", map[string]string{}, loc, allHeaders...)
		} else {
			age := -1
			if m := maxAgeRe.FindStringSubmatch(hsts); m != nil {
				if n, err := strconv.Atoi(m[1]); err == nil {
					age = n
				}
			}
			if age < hstsMinMaxAge {
				shown := strconv.Itoa(age)
				if age < 0 {
					shown = "0" // missing or unparsable max-age behaves like 0
				}
				add("hsts_weak", map[string]string{"max_age": shown}, loc, "Strict-Transport-Security")
			}
		}
	}

	if document && !strings.EqualFold(strings.TrimSpace(h.Get("X-Content-Type-Options")), "nosniff") {
		add("nosniff_missing", map[string]string{}, loc, "X-Content-Type-Options")
	}

	if document && strings.TrimSpace(h.Get("X-Frame-Options")) == "" && !frameAncestorsRe.MatchString(csp) {
		add("clickjacking_unprotected", map[string]string{}, loc, "Content-Security-Policy", "X-Frame-Options")
	}

	out = append(out, c.cookieFindings(resp)...)
	return out, nil
}

func (c SecurityHeaders) cookieFindings(resp *probe.Response) []evidence.Finding {
	var out []evidence.Finding
	https := resp.URL.Scheme == "https"
	seen := map[string]bool{}
	for _, raw := range resp.Header.Values("Set-Cookie") {
		cookies := (&http.Response{Header: http.Header{"Set-Cookie": {raw}}}).Cookies()
		if len(cookies) == 0 {
			continue
		}
		ck := cookies[0]
		if seen[ck.Name] {
			continue
		}
		seen[ck.Name] = true
		var missing []string
		if https && !ck.Secure {
			missing = append(missing, "Secure")
		}
		if !ck.HttpOnly {
			missing = append(missing, "HttpOnly")
		}
		// Absent attribute parses as 0; "SameSite" with no/unknown value as DefaultMode.
		if ck.SameSite == 0 || ck.SameSite == http.SameSiteDefaultMode {
			missing = append(missing, "SameSite")
		}
		if len(missing) == 0 {
			continue
		}
		location := resp.URL.String() + "#set-cookie=" + ck.Name
		out = append(out, evidence.New(c.ID(), "cookie_flags_missing",
			map[string]string{"cookie_name": ck.Name, "missing_flags": strings.Join(missing, ", ")},
			evidence.KindHttpHeader, location, "Set-Cookie: "+maskCookie(raw)))
	}
	return out
}

// maskCookie masks the cookie value and keeps the attributes.
func maskCookie(raw string) string {
	name, rest, ok := strings.Cut(raw, "=")
	if !ok {
		return evidence.Truncate(raw, 300)
	}
	value, attrs, _ := strings.Cut(rest, ";")
	out := name + "=" + evidence.MaskSecret(value)
	if attrs != "" {
		out += ";" + attrs
	}
	return evidence.Truncate(out, 300)
}
