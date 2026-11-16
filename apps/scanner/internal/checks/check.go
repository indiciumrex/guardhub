// Package checks holds the security checks. Each check lives in its own file,
// implements Check, and is registered in registry.go. Checks are pure and
// deterministic: they share no state, touch the network only through
// probe.Client (GET/HEAD only), detect by content signatures rather than
// status codes alone, and return raw technical findings with masked
// evidence. They never produce plain-language text (that is the API's job).
package checks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
)

// Check is one deterministic security check.
type Check interface {
	ID() string
	Run(ctx context.Context, target Target) ([]evidence.Finding, error)
}

// Target is what a check scans: a parsed origin and the per-scan probe client.
type Target struct {
	Origin *url.URL
	Probe  *probe.Client
}

// ErrInvalidOrigin is returned for targets that are not "scheme://host[:port]".
var ErrInvalidOrigin = errors.New("checks: target must be an http(s) origin without path, query or credentials")

// ErrTargetUnreachable is returned by a check when none of its requests got
// an HTTP response.
var ErrTargetUnreachable = errors.New("checks: target unreachable")

// ParseOrigin validates and normalises an origin ("https://Example.com/" →
// "https://example.com").
func ParseOrigin(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, ErrInvalidOrigin
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, ErrInvalidOrigin
	}
	return &url.URL{Scheme: u.Scheme, Host: strings.ToLower(u.Host)}, nil
}

// NewTarget builds a Target from an origin string.
func NewTarget(origin string, client *probe.Client) (Target, error) {
	u, err := ParseOrigin(origin)
	if err != nil {
		return Target{}, err
	}
	return Target{Origin: u, Probe: client}, nil
}

// URL returns the absolute URL of path on the target origin.
func (t Target) URL(path string) string {
	return t.Origin.Scheme + "://" + t.Origin.Host + path
}

// Host returns the lower-case hostname (no port).
func (t Target) Host() string { return strings.ToLower(t.Origin.Hostname()) }

// baselinePath is a fixed path that should not exist anywhere. Its response
// tells us how the site answers unknown paths (soft-404 detection) and is
// the 404 probe used by info_leak. Fixed (not random) to keep scans
// deterministic and to share one cached request between checks.
const baselinePath = "/guardhub-scanner-404-probe-7f3a9c1e"

// fetcher wraps probe calls for one check run: it separates fatal errors
// (context, budget, blocked target) from per-path failures, and remembers
// whether anything answered at all.
type fetcher struct {
	t        Target
	attempts int
	answered int
	lastErr  error
}

func newFetcher(t Target) *fetcher { return &fetcher{t: t} }

// get returns the response for path, nil when that path failed for a
// non-fatal reason, and an error only when the whole check must stop.
func (f *fetcher) get(ctx context.Context, path string) (*probe.Response, error) {
	return f.getURL(ctx, f.t.URL(path))
}

func (f *fetcher) getURL(ctx context.Context, rawURL string) (*probe.Response, error) {
	f.attempts++
	resp, err := f.t.Probe.Get(ctx, rawURL)
	if err == nil {
		f.answered++
		return resp, nil
	}
	f.lastErr = err
	if isFatal(ctx, err) {
		return nil, err
	}
	return nil, nil
}

// done returns the error a check should report after probing: nil if at
// least one request was answered (or none were made).
func (f *fetcher) done() error {
	if f.attempts > 0 && f.answered == 0 {
		return fmt.Errorf("%w: %w", ErrTargetUnreachable, f.lastErr)
	}
	return nil
}

func isFatal(ctx context.Context, err error) bool {
	return ctx.Err() != nil || errors.Is(err, probe.ErrBudgetExceeded) || errors.Is(err, probe.ErrBlockedAddress) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// baseline returns the response to a path that should not exist (may be nil).
func (f *fetcher) baseline(ctx context.Context) (*probe.Response, error) {
	return f.get(ctx, baselinePath)
}

// sameAsBaseline reports whether resp is just the site's generic answer for
// unknown paths (a soft-404 catch-all), which must never count as a hit.
func sameAsBaseline(resp, base *probe.Response) bool {
	if resp == nil || base == nil || base.StatusCode != resp.StatusCode {
		return false
	}
	return len(resp.Body) > 0 && bytes.Equal(resp.Body, base.Body)
}

var (
	titleRe    = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	spaceRe    = regexp.MustCompile(`\s+`)
	htmlMarkRe = regexp.MustCompile(`(?i)<!doctype html|<html[\s>]|<head[\s>]|<body[\s>]`)
)

// pageTitle returns the HTML <title>, whitespace-collapsed and shortened.
func pageTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	return evidence.Truncate(strings.TrimSpace(spaceRe.ReplaceAllString(string(m[1]), " ")), 120)
}

// looksLikeHTML reports whether body is an HTML document.
func looksLikeHTML(body []byte) bool {
	head := body
	if len(head) > 2048 {
		head = head[:2048]
	}
	return htmlMarkRe.Match(head)
}

func containsFold(body []byte, needle string) bool {
	return bytes.Contains(bytes.ToLower(body), []byte(strings.ToLower(needle)))
}

// signaturePayload builds a short evidence excerpt that names what was
// matched without copying page content (which could hold secrets).
func signaturePayload(resp *probe.Response, signature string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP %d %s\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		fmt.Fprintf(&b, "Content-Type: %s\n", ct)
	}
	if title := pageTitle(resp.Body); title != "" {
		fmt.Fprintf(&b, "Title: %s\n", title)
	}
	fmt.Fprintf(&b, "Matched signature: %s", signature)
	return b.String()
}

// headerPayload renders the listed response headers (only those present),
// in a stable order. Set-Cookie values are never included.
func headerPayload(resp *probe.Response, names ...string) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("HTTP %d %s", resp.StatusCode, http.StatusText(resp.StatusCode)))
	sort.Strings(names)
	for _, n := range names {
		for _, v := range resp.Header.Values(n) {
			lines = append(lines, n+": "+evidence.Truncate(v, 300))
		}
	}
	return strings.Join(lines, "\n")
}
