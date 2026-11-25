// Package activescan holds the active checks (ADR-0008) and the discovery
// they share. Every request goes through active.Client (scope guard, kill
// switch, budgets, breaker, request log); nothing here opens a connection.
package activescan

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"sort"
	"strings"

	htmlx "golang.org/x/net/html"

	"github.com/hksolutions/guardhub/apps/scanner/internal/active"
)

// Point is one injection point: a same-origin URL and one of its query
// parameters (GET only, ADR-0008 §4).
type Point struct {
	URL   *url.URL // with its original query (other parameters keep their values)
	Param string
}

// Key identifies a point independently of parameter values.
func (p Point) Key() string { return p.URL.Path + "?" + p.Param }

// Page is a fetched same-origin page discovery saw.
type Page struct {
	URL  *url.URL
	Resp *active.Response
}

// DiscoveryLimits bound the crawl.
type DiscoveryLimits struct {
	MaxPages  int // pages fetched (default 25)
	MaxDepth  int // link depth from the start URLs (default 2)
	MaxPoints int // injection points kept (default 30)
}

func (l DiscoveryLimits) withDefaults() DiscoveryLimits {
	if l.MaxPages <= 0 {
		l.MaxPages = 25
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = 2
	}
	if l.MaxPoints <= 0 {
		l.MaxPoints = 30
	}
	return l
}

// Discover crawls from the start URLs (the origin's / when none), following
// same-origin links and GET forms breadth-first, and returns the injection
// points (query parameters of links, inputs of GET forms) and the pages.
// Requests are logged under the module "discovery".
func Discover(ctx context.Context, c *active.Client, origin *url.URL, start []*url.URL, lim DiscoveryLimits) ([]Point, []Page, error) {
	return DiscoverAs(ctx, c, origin, start, lim, nil)
}

// DiscoverAs is Discover logged in as a consented test account (nil:
// anonymous). Links that look state-changing are never followed, with or
// without a session (unsafeLink).
func DiscoverAs(ctx context.Context, c *active.Client, origin *url.URL, start []*url.URL, lim DiscoveryLimits, sess *active.Session) ([]Point, []Page, error) {
	lim = lim.withDefaults()
	if len(start) == 0 {
		start = []*url.URL{origin.ResolveReference(&url.URL{Path: "/"})}
	}
	type item struct {
		u     *url.URL
		depth int
	}
	queue := make([]item, 0, len(start))
	seenPage := map[string]bool{}
	for _, u := range start {
		queue = append(queue, item{u, 0})
	}
	points := map[string]Point{}
	addPoint := func(u *url.URL, param string) {
		if len(points) >= lim.MaxPoints || param == "" {
			return
		}
		p := Point{URL: u, Param: param}
		if _, ok := points[p.Key()]; !ok {
			points[p.Key()] = p
		}
	}
	var pages []Page
	for len(queue) > 0 && len(pages) < lim.MaxPages {
		it := queue[0]
		queue = queue[1:]
		pageKey := it.u.Path + "?" + sortedKeys(it.u.Query())
		if seenPage[pageKey] {
			continue
		}
		seenPage[pageKey] = true
		if unsafeLink(it.u) {
			continue // neither requested nor probed
		}
		for k := range it.u.Query() {
			addPoint(it.u, k)
		}
		resp, err := c.Send(ctx, active.AsSession(active.Baseline("discovery", it.u), sess))
		if err != nil {
			if fatal(err) || errors.Is(err, active.ErrModuleBudget) {
				return sortedPoints(points), pages, err // module budget: what was found so far
			}
			continue
		}
		if resp == nil {
			continue
		}
		if resp.Status == 401 || resp.Status == 403 {
			// an endpoint behind a login: nothing to follow, but its headers count (an API that
			// answers 401 to an anonymous scan can still grant a foreign origin a credentialed
			// read, active_cors). IDOR only uses pages that answered 200.
			pages = append(pages, Page{URL: resp.URL, Resp: resp})
			continue
		}
		if resp.Status != 200 {
			continue
		}
		pages = append(pages, Page{URL: resp.URL, Resp: resp})
		if !isHTML(resp) {
			continue
		}
		links, forms := parseLinks(resp.URL, resp.Body)
		forms = safeForms(forms) // state-changing forms are neither requested nor probed
		for _, f := range forms {
			for _, in := range f.inputs {
				addPoint(f.action, in)
			}
		}
		if it.depth >= lim.MaxDepth {
			continue
		}
		for _, l := range links {
			if sameOrigin(origin, l) && !staticAsset(l.Path) {
				// A link's own parameters are injection points as soon as it is seen: they need
				// no request to be known, and the page cap must not hide them (DVWA's open
				// redirect links sit one level below 25 other pages). Unsafe links never count.
				if !unsafeLink(l) {
					for k := range l.Query() {
						addPoint(l, k)
					}
				}
				queue = append(queue, item{l, it.depth + 1})
			}
		}
		for _, f := range forms {
			if sameOrigin(origin, f.action) && !staticAsset(f.action.Path) {
				queue = append(queue, item{f.action, it.depth + 1})
			}
		}
	}
	return sortedPoints(points), pages, nil
}

// fatal errors end the whole active scan (kill switch, breaker, budget).
func fatal(err error) bool {
	return errors.Is(err, active.ErrKilled) || errors.Is(err, active.ErrBreaker) || errors.Is(err, active.ErrBudget)
}

type form struct {
	action *url.URL
	inputs []string
	// unsafe: a password field or a submit control that names a change
	// (e.g. DVWA's GET password-change form). Never requested, never probed.
	unsafe bool
}

// mutatingSubmits are submit names/values that mark a GET form as changing
// state. Search-like submits ("Submit", "Search", "Go") stay allowed.
var mutatingSubmits = []string{"change", "update", "save", "delete", "remove", "add", "create", "edit",
	"set", "send", "post", "upload", "buy", "pay", "order", "register", "subscribe", "transfer",
	"confirm", "apply", "reset", "login", "logout", "sign", "vote", "rate", "comment", "publish"}

func mutatingSubmit(nameOrValue string) bool {
	v := strings.ToLower(nameOrValue)
	for _, w := range mutatingSubmits {
		if strings.Contains(v, w) {
			return true
		}
	}
	return false
}

// parseLinks returns same-document links and GET forms (action with the
// inputs' names; their default values become the query of the action URL).
func parseLinks(base *url.URL, body []byte) ([]*url.URL, []form) {
	var links []*url.URL
	var forms []form
	var cur *form
	z := htmlx.NewTokenizer(bytes.NewReader(body))
	for {
		tt := z.Next()
		if tt == htmlx.ErrorToken {
			break
		}
		tok := z.Token()
		switch {
		case tt == htmlx.EndTagToken && tok.Data == "form":
			if cur != nil {
				forms = append(forms, *cur)
				cur = nil
			}
		case tt == htmlx.StartTagToken || tt == htmlx.SelfClosingTagToken:
			attr := func(k string) string {
				for _, a := range tok.Attr {
					if a.Key == k {
						return strings.TrimSpace(a.Val)
					}
				}
				return ""
			}
			switch tok.Data {
			case "a":
				if u, err := base.Parse(attr("href")); err == nil && attr("href") != "" {
					u.Fragment = ""
					links = append(links, u)
				}
			case "form":
				if m := strings.ToLower(attr("method")); m != "" && m != "get" {
					cur = nil // POST forms are out of scope (ADR-0008 §4)
					continue
				}
				action := attr("action")
				u, err := base.Parse(action)
				if err != nil {
					continue
				}
				u.Fragment = ""
				cur = &form{action: u}
			case "input", "select", "textarea":
				if cur == nil {
					continue
				}
				name := attr("name")
				typ := strings.ToLower(attr("type"))
				lname := strings.ToLower(name)
				if typ == "password" || strings.Contains(lname, "password") || strings.Contains(lname, "passwd") || lname == "pass" || lname == "pwd" {
					cur.unsafe = true
					continue
				}
				if (typ == "submit" || typ == "button" || tok.Data == "button") && (mutatingSubmit(name) || mutatingSubmit(attr("value"))) {
					cur.unsafe = true
				}
				if name == "" || typ == "file" {
					continue
				}
				q := cur.action.Query()
				if !q.Has(name) {
					v := attr("value")
					if v == "" && typ != "submit" && typ != "hidden" {
						v = "1"
					}
					q.Set(name, v)
					cur.action.RawQuery = q.Encode()
				}
				if typ != "submit" && typ != "hidden" && typ != "button" {
					cur.inputs = append(cur.inputs, name)
				}
			}
		}
	}
	if cur != nil {
		forms = append(forms, *cur)
	}
	return links, forms
}

// safeForms drops forms that look state-changing (form.unsafe) or whose
// action is an unsafe link.
func safeForms(fs []form) []form {
	out := fs[:0]
	for _, f := range fs {
		if !f.unsafe && !unsafeLink(f.action) {
			out = append(out, f)
		}
	}
	return out
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

func staticAsset(path string) bool {
	p := strings.ToLower(path)
	for _, ext := range []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".pdf", ".zip", ".mp4", ".webp", ".map"} {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	// never crawl into logout links: they end the user's session
	return strings.Contains(p, "logout") || strings.Contains(p, "logoff") || strings.Contains(p, "signout")
}

// unsafeVerbs are words that mark a GET link as doing something (a badly
// built site may delete, pay or log out on GET). Do-no-harm: never request one.
var unsafeVerbs = []string{"delete", "remove", "destroy", "drop", "cancel", "unsubscribe", "revoke",
	"disable", "deactivate", "reset", "approve", "reject", "transfer", "withdraw", "pay", "purchase",
	"buy", "checkout", "order/place", "confirm", "logout", "logoff", "signout", "sign-out", "log-out",
	"setup", "install", "truncate", "purge", "archive", "ban", "kick", "promote", "upgrade", "downgrade"}

// unsafeLink reports whether u's path, parameter names or values carry one of
// unsafeVerbs (as a whole word-ish token) or an action/do/op parameter.
func unsafeLink(u *url.URL) bool {
	hay := strings.ToLower(u.Path)
	for k, vs := range u.Query() {
		lk := strings.ToLower(k)
		if lk == "action" || lk == "do" || lk == "op" || lk == "cmd" || lk == "task" || lk == "mode" {
			return true
		}
		hay += " " + lk + " " + strings.ToLower(strings.Join(vs, " "))
	}
	for _, v := range unsafeVerbs {
		if strings.Contains(hay, v) {
			return true
		}
	}
	return false
}

func isHTML(r *active.Response) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "html")
}

func sortedKeys(q url.Values) string {
	ks := make([]string, 0, len(q))
	for k := range q {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return strings.Join(ks, "&")
}

func sortedPoints(m map[string]Point) []Point {
	out := make([]Point, 0, len(m))
	for _, p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}
