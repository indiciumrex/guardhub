package checks

// js_secrets (ADR-0007, "content signals: keys in JS bundles"): credentials
// shipped to every visitor's browser, in the home page's HTML (inline scripts,
// attributes) or in its same-origin scripts (docs/checks/js_secrets.md).
//
// The provider rules are repo_secrets' (secret_rules.go): a fixed prefix or
// structure only that provider's credentials have, plus the placeholder and
// entropy filters. Publishable keys meant for browsers (Google browser API
// keys, Stripe publishable keys, Firebase web config) have no rule. The
// generic "password = ..." rule is not used here: minified code is full of
// such names with labels as values.
//
//   - secret_in_javascript: a live credential (repo_secrets' hardcoded_secret
//     rules).
//   - test_secret_in_javascript: a test-mode credential (e.g. Stripe sk_test_).
//
// Scripts: the first 10 <script src> tags of the home page, at most 6
// same-origin ones fetched, each read up to the probe's 256 KiB. Cross-origin
// scripts are never fetched. Evidence holds masked values only.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/repo"
)

// JSSecrets implements the js_secrets check.
type JSSecrets struct{}

// ID implements Check.
func (JSSecrets) ID() string { return evidence.CheckJsSecrets }

// Run implements Check.
func (c JSSecrets) Run(ctx context.Context, t Target) ([]evidence.Finding, error) {
	f := newFetcher(t)
	root, err := f.get(ctx, "/")
	if err != nil {
		return nil, err
	}
	if root == nil || root.StatusCode != 200 || root.RedirectRefused || !isHTMLDocument(root) {
		return nil, f.done()
	}
	type source struct {
		url  string
		body []byte
	}
	sources := []source{{url: root.URL.String(), body: root.Body}}
	fetched := 0
	for i, m := range scriptSrcRe.FindAllSubmatch(root.Body, -1) {
		if i == jsMaxScripts || fetched == jsMaxFetches {
			break
		}
		js, ok := sameOrigin(root.URL, string(m[1]))
		if !ok {
			continue
		}
		fetched++
		resp, err := f.getURL(ctx, js.String())
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.StatusCode != 200 || resp.RedirectRefused || isHTMLDocument(resp) {
			continue // an HTML answer is an error page or a catch-all, not the script
		}
		sources = append(sources, source{url: js.String(), body: resp.Body})
	}
	var out []evidence.Finding
	for _, s := range sources {
		hits := scanFileForSecrets(repo.File{Path: s.url, Data: s.body})
		sort.Slice(hits, func(i, j int) bool { return hits[i].rule < hits[j].rule })
		for _, h := range hits {
			var key string
			switch h.key {
			case "hardcoded_secret":
				key = "secret_in_javascript"
			case "test_mode_secret":
				key = "test_secret_in_javascript"
			default:
				continue // generic_secret: not used on browser code
			}
			payload := fmt.Sprintf("rule %s in %s (line %d): value %s", h.rule, s.url, h.line, evidence.MaskSecret(h.firstValue))
			if n := len(h.values); n > 1 {
				payload += fmt.Sprintf(" and %d more", n-1)
			}
			out = append(out, evidence.New(c.ID(), key, map[string]string{
				"secret_type": h.paramValue,
				"script":      evidence.Truncate(s.url, 200),
				"count":       fmt.Sprint(len(h.values)),
			}, evidence.KindHttpResponse, s.url+"#"+h.rule, payload))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return strings.Compare(out[i].Evidence.Location, out[j].Evidence.Location) < 0 })
	return out, f.done()
}
