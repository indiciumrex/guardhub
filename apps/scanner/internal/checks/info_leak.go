package checks

// info_leak: technical details a site gives away: software versions in
// headers, stack traces and debug pages on a 404 probe, and directory
// listings. Only GETs of the root, one fixed non-existent path and a few
// common asset directories.

import (
	"context"
	"regexp"
	"strings"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
)

// InfoLeak implements the info_leak check.
type InfoLeak struct{}

// ID implements Check.
func (InfoLeak) ID() string { return evidence.CheckInfoLeak }

var (
	serverVersionRe    = regexp.MustCompile(`[A-Za-z][\w.\-]*/\d+(?:\.\d+)*`)
	frameworkVersionRe = regexp.MustCompile(`\d+\.\d+|/\d+`)
	anyDigitRe         = regexp.MustCompile(`\d`)

	// Stack trace signatures, checked in order.
	stackTraceSigs = []struct {
		name string
		re   *regexp.Regexp
	}{
		{"Python traceback", regexp.MustCompile(`Traceback \(most recent call last\):`)},
		{"Java stack trace", regexp.MustCompile(`\bat [\w$.]+\([\w$]+\.java:\d+\)`)},
		{".NET stack trace", regexp.MustCompile(`Server Error in '[^']*' Application|\bat [\w.<>` + "`" + `+]+\([^)\n]*\) in [^\n]+:line \d+`)},
		{"PHP error", regexp.MustCompile(`(?i)\b(?:fatal error|parse error|uncaught exception|warning|notice)\b(?:</b>)?:[\s\S]{0,800}?\bon line\s*(?:<b>)?\s*\d+`)},
		{"Node.js stack trace", regexp.MustCompile(`\n\s+at [^\n]*\((?:/|[A-Za-z]:\\)[^)\n]+\.(?:js|mjs|cjs|ts):\d+:\d+\)`)},
		{"Ruby backtrace", regexp.MustCompile(`\.rb:\d+:in [` + "`" + `']`)},
	}

	// Debug-mode signatures: framework → predicate.
	debugSigs = []struct {
		framework string
		match     func([]byte) bool
	}{
		{"Django", bodyAll("DEBUG = True", "django")},
		{"Laravel", func(b []byte) bool {
			return bodyAll("laravel")(b) && bodyAny("ignition", "window.ignite")(b)
		}},
		{"Ruby on Rails", bodyAny("Action Controller: Exception caught", "Rails.root:")},
		{"Flask (Werkzeug)", bodyAny("Werkzeug Debugger", "__debugger__")},
	}

	directoryListingRe = regexp.MustCompile(`(?i)<title>\s*Index of /|<h1>\s*Index of /|<title>\s*Directory listing for /|\[To Parent Directory\]`)
)

// listingPaths: root first, then common asset directories.
var listingPaths = []string{"/", "/uploads/", "/images/", "/assets/", "/static/", "/backup/"}

// Run implements Check.
func (c InfoLeak) Run(ctx context.Context, t Target) ([]evidence.Finding, error) {
	f := newFetcher(t)
	var out []evidence.Finding

	root, err := f.get(ctx, "/")
	if err != nil {
		return nil, err
	}
	if root != nil {
		out = append(out, c.headerFindings(root)...)
	}

	notFound, err := f.baseline(ctx)
	if err != nil {
		return out, err
	}

	// Debug pages and stack traces: on the 404 probe first, then the root.
	debugSeen := false
	for _, page := range []struct {
		resp *probe.Response
		path string
	}{{notFound, baselinePath}, {root, "/"}} {
		if page.resp == nil || debugSeen {
			continue
		}
		if fw, ok := debugFramework(page.resp.Body); ok {
			debugSeen = true
			out = append(out, evidence.New(c.ID(), "debug_mode_enabled", map[string]string{"framework": fw},
				evidence.KindHttpResponse, t.URL(page.path), signaturePayload(page.resp, fw+" debug page")))
			continue
		}
		if name, line, ok := stackTrace(page.resp.Body); ok {
			out = append(out, evidence.New(c.ID(), "stack_trace_exposed", map[string]string{"path": page.path},
				evidence.KindHttpResponse, t.URL(page.path), signaturePayload(page.resp, name)+"\nExcerpt: "+line))
			break
		}
	}

	// One directory-listing finding is enough: the fix is server-wide.
	for _, p := range listingPaths {
		resp, err := f.get(ctx, p)
		if err != nil {
			return out, err
		}
		if resp != nil && resp.StatusCode == 200 && directoryListingRe.Match(resp.Body) && !sameAsBaseline(resp, notFound) {
			out = append(out, evidence.New(c.ID(), "directory_listing_enabled", map[string]string{"path": p},
				evidence.KindHttpResponse, t.URL(p), signaturePayload(resp, `"Index of /" directory listing`)))
			break
		}
	}
	return out, f.done()
}

func (c InfoLeak) headerFindings(resp *probe.Response) []evidence.Finding {
	var out []evidence.Finding
	loc := resp.URL.String()
	if v := strings.TrimSpace(resp.Header.Get("Server")); v != "" && serverVersionRe.MatchString(v) {
		out = append(out, evidence.New(c.ID(), "server_version_disclosed", map[string]string{"header": "Server", "value": v},
			evidence.KindHttpHeader, loc+"#header=Server", "Server: "+v))
	}
	for _, h := range []string{"X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"} {
		v := strings.TrimSpace(resp.Header.Get(h))
		if v == "" {
			continue
		}
		versioned := frameworkVersionRe.MatchString(v)
		if h != "X-Powered-By" {
			versioned = anyDigitRe.MatchString(v)
		}
		if versioned {
			out = append(out, evidence.New(c.ID(), "framework_version_disclosed", map[string]string{"header": h, "value": v},
				evidence.KindHttpHeader, loc+"#header="+h, h+": "+v))
		}
	}
	return out
}

func debugFramework(body []byte) (string, bool) {
	for _, s := range debugSigs {
		if s.match(body) {
			return s.framework, true
		}
	}
	return "", false
}

// stackTrace returns the signature name and the matched line (masked,
// shortened) when body contains a stack trace.
func stackTrace(body []byte) (string, string, bool) {
	for _, s := range stackTraceSigs {
		if loc := s.re.FindIndex(body); loc != nil {
			line := strings.TrimSpace(string(body[loc[0]:loc[1]]))
			return s.name, evidence.MaskURLCredentials(evidence.Truncate(line, 200)), true
		}
	}
	return "", "", false
}
