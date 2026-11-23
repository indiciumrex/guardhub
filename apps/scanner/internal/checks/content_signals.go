package checks

// content_signals (ADR-0007, "content signals"): what the home page's HTML
// makes a browser load (docs/checks/content_signals.md).
//
//   - mixed_content_active: an HTTPS page loads a script, stylesheet or iframe
//     over plain http://. Browsers block it (the page breaks), and where it
//     loads, an attacker on the network can replace it.
//   - mixed_content_passive: an HTTPS page loads an image, audio or video over
//     http://. Current browsers upgrade or warn; older ones load it in clear.
//   - sri_missing: a script from another site (another registrable domain) is
//     loaded over https without an integrity attribute (Subresource
//     Integrity), so whoever controls that site controls this page.
//
// The page is parsed as HTML (golang.org/x/net/html tokenizer): comments,
// <noscript> and <template> contents, links (<a href>) and text never count.
// http:// URLs on potentially trustworthy hosts (localhost, loopback) are not
// mixed content. Nothing beyond the home page is requested.

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	htmlx "golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
)

// ContentSignals implements the content_signals check.
type ContentSignals struct{}

// ID implements Check.
func (ContentSignals) ID() string { return evidence.CheckContentSignals }

const csMaxListed = 5 // resources named in the evidence

// csResource is one subresource the page makes the browser load.
type csResource struct {
	kind      string // script, stylesheet, iframe, image, audio, video
	url       *url.URL
	integrity bool
}

// Run implements Check.
func (c ContentSignals) Run(ctx context.Context, t Target) ([]evidence.Finding, error) {
	f := newFetcher(t)
	root, err := f.get(ctx, "/")
	if err != nil {
		return nil, err
	}
	if root == nil || root.StatusCode != 200 || root.RedirectRefused || !isHTMLDocument(root) {
		return nil, f.done()
	}
	page := root.URL
	res := subresources(page, root.Body)

	var active, passive, sri []csResource
	for _, r := range res {
		switch {
		case page.Scheme == "https" && r.url.Scheme == "http" && !trustworthyHost(r.url.Hostname()):
			if r.kind == "script" || r.kind == "stylesheet" || r.kind == "iframe" {
				active = append(active, r)
			} else {
				passive = append(passive, r)
			}
		case r.kind == "script" && r.url.Scheme == "https" && !r.integrity && crossSite(page.Hostname(), r.url.Hostname()):
			sri = append(sri, r)
		}
	}
	var out []evidence.Finding
	add := func(key string, rs []csResource, intro string) {
		if len(rs) == 0 {
			return
		}
		var b strings.Builder
		fmt.Fprintf(&b, "GET %s -> HTTP 200 (HTML). %s:\n", page.String(), intro)
		for i, r := range rs {
			if i == csMaxListed {
				fmt.Fprintf(&b, "... and %d more\n", len(rs)-csMaxListed)
				break
			}
			fmt.Fprintf(&b, "%s %s\n", r.kind, evidence.Truncate(r.url.String(), 200))
		}
		out = append(out, evidence.New(c.ID(), key, map[string]string{
			"count":   strconv.Itoa(len(rs)),
			"example": evidence.Truncate(rs[0].url.String(), 200),
		}, evidence.KindHttpResponse, page.String(), strings.TrimRight(b.String(), "\n")))
	}
	add("mixed_content_active", active, "This HTTPS page loads scripts, stylesheets or frames over http://")
	add("mixed_content_passive", passive, "This HTTPS page loads images, audio or video over http://")
	add("sri_missing", sri, "Scripts from other sites loaded without an integrity attribute")
	return out, nil
}

// subresources lists what the page's HTML makes a browser fetch: scripts,
// stylesheets, iframes, images, audio and video (with their <source>s).
func subresources(page *url.URL, body []byte) []csResource {
	base := page
	var out []csResource
	z := htmlx.NewTokenizer(bytes.NewReader(body))
	template, media := 0, 0
	for {
		tt := z.Next()
		if tt == htmlx.ErrorToken {
			return out
		}
		tok := z.Token()
		name := tok.Data
		if tt == htmlx.EndTagToken {
			switch name {
			case "template":
				if template > 0 {
					template--
				}
			case "audio", "video":
				if media > 0 {
					media--
				}
			}
			continue
		}
		if tt != htmlx.StartTagToken && tt != htmlx.SelfClosingTagToken {
			continue
		}
		if name == "template" {
			if tt == htmlx.StartTagToken {
				template++
			}
			continue
		}
		if template > 0 {
			continue // inert until a script clones it
		}
		attr := func(k string) (string, bool) {
			for _, a := range tok.Attr {
				if a.Namespace == "" && a.Key == k {
					return strings.TrimSpace(a.Val), true
				}
			}
			return "", false
		}
		ref, kind := "", ""
		switch name {
		case "base":
			if href, ok := attr("href"); ok && base == page {
				if u, err := page.Parse(href); err == nil {
					base = u
				}
			}
			continue
		case "script":
			ref, _ = attr("src")
			kind = "script"
		case "link":
			rel, _ := attr("rel")
			if hasToken(rel, "stylesheet") {
				ref, _ = attr("href")
				kind = "stylesheet"
			}
		case "iframe":
			ref, _ = attr("src")
			kind = "iframe"
		case "img":
			ref, _ = attr("src")
			kind = "image"
		case "audio", "video":
			if tt == htmlx.StartTagToken {
				media++
			}
			ref, _ = attr("src")
			kind = name
		case "source":
			if media > 0 {
				ref, _ = attr("src")
				kind = "media"
			}
		}
		if ref == "" || kind == "" {
			continue
		}
		u, err := base.Parse(ref)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			continue
		}
		u.Fragment = ""
		integrity, _ := attr("integrity")
		out = append(out, csResource{kind: kind, url: u, integrity: integrity != ""})
	}
}

func hasToken(list, tok string) bool {
	for _, t := range strings.Fields(strings.ToLower(list)) {
		if t == tok {
			return true
		}
	}
	return false
}

// trustworthyHost: hosts whose http:// URLs browsers do not treat as mixed
// content (W3C Secure Contexts: localhost and loopback).
func trustworthyHost(h string) bool {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// crossSite reports whether two hosts belong to different sites (registrable
// domains, eTLD+1; IP addresses compare exactly).
func crossSite(a, b string) bool {
	a, b = strings.ToLower(strings.TrimSuffix(a, ".")), strings.ToLower(strings.TrimSuffix(b, "."))
	if a == b {
		return false
	}
	if net.ParseIP(a) != nil || net.ParseIP(b) != nil {
		return true
	}
	ra, errA := publicsuffix.EffectiveTLDPlusOne(a)
	rb, errB := publicsuffix.EffectiveTLDPlusOne(b)
	if errA != nil || errB != nil {
		return true
	}
	return ra != rb
}
