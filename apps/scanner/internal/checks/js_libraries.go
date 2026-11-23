package checks

// js_libraries (ADR-0007, "technology + known CVEs"): JavaScript libraries the
// home page loads, at a version GuardHub is CERTAIN of, matched against OSV
// advisories for that exact npm version (docs/checks/js_libraries.md).
//
// A version is certain only when it comes from
//   - the library's own banner comment inside the script (same-origin scripts,
//     fetched), e.g. "/*! jQuery v1.12.4 | (c) jQuery Foundation", or
//   - the path of a well-known public CDN that serves exactly one version per
//     URL (code.jquery.com, cdnjs, jsDelivr, unpkg, Google Hosted Libraries,
//     BootstrapCDN); cross-origin scripts are never fetched.
//
// File names alone ("jquery-1.8.3.min.js" on the site itself) are never
// trusted: a renamed or patched file would be reported wrongly. Server
// software versions (Server, X-Powered-By) are out of scope: distributions
// backport fixes without changing the version, so the version does not
// decide the vulnerability (info_leak reports the disclosure itself).
//
// Only npm package names and versions are sent to OSV (ADR-0006 §7), never
// the target. One finding per (library, version).

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/hksolutions/guardhub/apps/scanner/internal/deps"
	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
)

// JSLibraries implements the js_libraries check.
type JSLibraries struct {
	OSV *deps.OSV
}

// ID implements Check.
func (JSLibraries) ID() string { return evidence.CheckJsLibraries }

const (
	jsMaxScripts = 10 // <script src> tags read from the home page
	jsMaxFetches = 6  // same-origin scripts fetched
	jsVersion    = `(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)`
)

// jsLibrary is one recognised library: its npm name, the banner its own
// distribution files start with, and its names on the CDNs.
type jsLibrary struct {
	npm    string
	banner *regexp.Regexp
	cdnjs  string // cdnjs.cloudflare.com/ajax/libs/<cdnjs>/<version>/
	google string // ajax.googleapis.com/ajax/libs/<google>/<version>/
}

var jsLibraries = []jsLibrary{
	{npm: "jquery", banner: regexp.MustCompile(`/\*!?\s*(?:\*\s*)?jQuery (?:JavaScript Library )?v` + jsVersion + `\b`), cdnjs: "jquery", google: "jquery"},
	{npm: "jquery-ui", banner: regexp.MustCompile(`/\*!\s*jQuery UI - v` + jsVersion + `\b`), cdnjs: "jqueryui", google: "jqueryui"},
	{npm: "jquery-migrate", banner: regexp.MustCompile(`/\*!\s*(?:\*\s*)?jQuery Migrate (?:- )?v` + jsVersion + `\b`), cdnjs: "jquery-migrate"},
	{npm: "bootstrap", banner: regexp.MustCompile(`/\*!\s*\n?\s*\*?\s*Bootstrap v` + jsVersion + ` \(https?://getbootstrap\.com`), cdnjs: "twitter-bootstrap"},
	{npm: "angular", banner: regexp.MustCompile(`@license AngularJS v` + jsVersion + `\b`), cdnjs: "angular.js", google: "angularjs"},
	{npm: "moment", banner: regexp.MustCompile(`//! moment\.js\s*\n//! version : ` + jsVersion + `\b`), cdnjs: "moment.js"},
	{npm: "handlebars", banner: regexp.MustCompile(`@license\s+handlebars v` + jsVersion + `\b`), cdnjs: "handlebars.js"},
	{npm: "dompurify", banner: regexp.MustCompile(`/\*! @license DOMPurify ` + jsVersion + `\b`), cdnjs: "dompurify"},
	{npm: "vue", banner: regexp.MustCompile(`/\*!\s*\n\s*\* Vue\.js v` + jsVersion + `\b`), cdnjs: "vue"},
	{npm: "knockout", banner: regexp.MustCompile(`Knockout JavaScript library v` + jsVersion + `\b`), cdnjs: "knockout"},
}

var (
	codeJQueryRe = regexp.MustCompile(`^/(?:(ui)/` + jsVersion + `/jquery-ui(?:\.min)?\.js|jquery-(migrate-)?` + jsVersion + `(?:\.slim)?(?:\.min)?\.js)$`)
	cdnjsRe      = regexp.MustCompile(`^/ajax/libs/([a-z0-9.-]+)/` + jsVersion + `/`)
	googleRe     = regexp.MustCompile(`^/ajax/libs/([a-z0-9.-]+)/` + jsVersion + `/`)
	npmCDNRe     = regexp.MustCompile(`^/(?:npm/)?([a-z0-9][a-z0-9._-]*)@` + jsVersion + `(?:/|$)`)
	bootCDNRe    = regexp.MustCompile(`^/(?:twitter-)?bootstrap/` + jsVersion + `/js/bootstrap(?:\.bundle)?(?:\.min)?\.js$`)
)

// jsHit is one library found at a certain version.
type jsHit struct {
	pkg    deps.Package
	script string // absolute script URL
	how    string // evidence line: where the version came from
}

// Run implements Check.
func (c JSLibraries) Run(ctx context.Context, t Target) ([]evidence.Finding, error) {
	f := newFetcher(t)
	root, err := f.get(ctx, "/")
	if err != nil {
		return nil, err
	}
	if root == nil || root.StatusCode != 200 || root.RedirectRefused {
		return nil, f.done()
	}
	var hits []jsHit
	seen := map[string]bool{}
	add := func(h jsHit) {
		k := h.pkg.Name + "@" + h.pkg.Version
		if !seen[k] {
			seen[k] = true
			hits = append(hits, h)
		}
	}
	fetched := 0
	for i, m := range scriptSrcRe.FindAllSubmatch(root.Body, -1) {
		if i == jsMaxScripts {
			break
		}
		src, err := root.URL.Parse(strings.TrimSpace(string(m[1])))
		if err != nil || (src.Scheme != "http" && src.Scheme != "https") {
			continue
		}
		src.Fragment = ""
		if src.Scheme != root.URL.Scheme || !strings.EqualFold(src.Host, root.URL.Host) {
			if lib, ver, ok := fromCDN(src); ok {
				add(jsHit{pkg: deps.Package{Ecosystem: "npm", Name: lib, Version: ver}, script: src.String(),
					how: fmt.Sprintf("home page loads %s (%s %s: the version is part of the CDN path)", src.String(), lib, ver)})
			}
			continue
		}
		if fetched == jsMaxFetches {
			continue
		}
		fetched++
		resp, err := f.getURL(ctx, src.String())
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.StatusCode != 200 || resp.RedirectRefused {
			continue
		}
		for _, lib := range jsLibraries {
			if mm := lib.banner.FindSubmatch(resp.Body); mm != nil {
				ver := string(mm[1])
				add(jsHit{pkg: deps.Package{Ecosystem: "npm", Name: lib.npm, Version: ver}, script: src.String(),
					how: fmt.Sprintf("GET %s -> HTTP 200, banner %q", src.Path, evidence.Truncate(strings.TrimSpace(string(mm[0])), 80))})
			}
		}
	}
	if err := f.done(); err != nil {
		return nil, err
	}
	if len(hits) == 0 {
		return nil, nil
	}
	if c.OSV == nil {
		return nil, errors.New("js_libraries: no OSV client configured")
	}
	pkgs := make([]deps.Package, len(hits))
	for i, h := range hits {
		pkgs[i] = h.pkg
	}
	matches, err := c.OSV.Matches(ctx, pkgs)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, m := range matches {
		ids = append(ids, m...)
	}
	records, err := c.OSV.Vulns(ctx, ids)
	if err != nil && !errors.Is(err, deps.ErrTooManyAdvisories) {
		return nil, err
	}
	runErr := err
	var out []evidence.Finding
	for i, h := range hits {
		var recs []*deps.Vuln
		complete := len(matches[i]) > 0
		for _, id := range matches[i] {
			r, ok := records[id]
			if !ok {
				complete = false
				break
			}
			recs = append(recs, r)
		}
		if !complete {
			continue // no advisories, or over the advisory cap: never guessed
		}
		verdict, ok := deps.Assess(h.pkg, recs)
		if !ok {
			continue // every advisory was withdrawn
		}
		out = append(out, c.finding(h, verdict))
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Params["library"] < out[b].Params["library"] })
	return out, runErr
}

func (c JSLibraries) finding(h jsHit, v deps.Verdict) evidence.Finding {
	ids := v.IDs()
	shown := ids
	if len(shown) > maxAdvisoryIDs {
		shown = append(append([]string(nil), ids[:maxAdvisoryIDs]...), fmt.Sprintf("+%d", len(ids)-maxAdvisoryIDs))
	}
	fixed := v.Fixed
	if fixed == "" {
		fixed = "-"
	}
	var b strings.Builder
	b.WriteString(h.how + "\n")
	fmt.Fprintf(&b, "OSV, npm %s@%s:\n", h.pkg.Name, h.pkg.Version)
	for _, is := range v.Issues {
		fix := is.Fixed
		if fix == "" {
			fix = "no fixed version"
		}
		fmt.Fprintf(&b, "%s: %s, fixed in %s\n", is.ID, ratingLabel(is.Rating), fix)
	}
	return evidence.New(evidence.CheckJsLibraries, "vulnerable_js_library", map[string]string{
		"library":       h.pkg.Name,
		"version":       h.pkg.Version,
		"advisories":    strings.Join(shown, ", "),
		"fixed_version": fixed,
		"script":        evidence.Truncate(h.script, 200),
	}, evidence.KindHttpResponse, h.script, strings.TrimRight(b.String(), "\n"))
}

// fromCDN reads (npm name, version) from the path of a well-known CDN URL.
func fromCDN(u *url.URL) (string, string, bool) {
	host := strings.ToLower(u.Hostname())
	p := u.Path
	switch host {
	case "code.jquery.com":
		if m := codeJQueryRe.FindStringSubmatch(p); m != nil {
			switch {
			case m[1] == "ui":
				return "jquery-ui", m[2], true
			case m[3] != "":
				return "jquery-migrate", m[4], true
			default:
				return "jquery", m[4], true
			}
		}
	case "cdnjs.cloudflare.com":
		if m := cdnjsRe.FindStringSubmatch(p); m != nil {
			for _, l := range jsLibraries {
				if l.cdnjs == m[1] || (m[1] == "bootstrap" && l.npm == "bootstrap") {
					return l.npm, m[2], true
				}
			}
		}
	case "ajax.googleapis.com":
		if m := googleRe.FindStringSubmatch(p); m != nil {
			for _, l := range jsLibraries {
				if l.google != "" && l.google == m[1] {
					return l.npm, m[2], true
				}
			}
		}
	case "cdn.jsdelivr.net", "unpkg.com":
		if host == "cdn.jsdelivr.net" && !strings.HasPrefix(p, "/npm/") {
			return "", "", false
		}
		if m := npmCDNRe.FindStringSubmatch(p); m != nil {
			for _, l := range jsLibraries {
				if l.npm == m[1] {
					return l.npm, m[2], true
				}
			}
		}
	case "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com", "netdna.bootstrapcdn.com":
		if m := bootCDNRe.FindStringSubmatch(p); m != nil {
			return "bootstrap", m[1], true
		}
	}
	return "", "", false
}
