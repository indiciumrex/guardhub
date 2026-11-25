package activescan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"
	"time"

	htmlx "golang.org/x/net/html"

	"github.com/hksolutions/guardhub/apps/scanner/internal/active"
	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
)

// Env is what every active check gets: the fenced client and discovery's
// results.
type Env struct {
	Client *active.Client
	Origin *url.URL
	Points []Point
	Pages  []Page
	Collab active.Collaborator // nil: SSRF is not run
	// OOBWait is how long SSRF waits for a collaborator hit (default 5s).
	OOBWait time.Duration
	// SessionA/SessionB: two consented test accounts (nil: IDOR is not run).
	SessionA, SessionB *active.Session
	// Start: the start URLs discovery began with (the origin's "/" first);
	// IDOR's own discovery as account A uses them too.
	Start []*url.URL
}

// Check is one active check.
type Check interface {
	ID() string
	Run(ctx context.Context, env Env) ([]evidence.Finding, error)
}

// All returns the active checks in run order.
func All() []Check { return []Check{XSS{}, SQLi{}, Redirect{}, CORS{}, SSRF{}, IDOR{}} }

// IsFatal reports whether err ends the whole active scan.
func IsFatal(err error) bool {
	return errors.Is(err, active.ErrKilled) || errors.Is(err, active.ErrBreaker) || errors.Is(err, active.ErrBudget)
}

func payload(id string) active.Payload {
	p, ok := active.PayloadByID(id)
	if !ok {
		panic("activescan: missing catalogue payload " + id)
	}
	return p
}

// endsCheck reports whether err ends the running check: a fatal stop, or
// the check's own request budget is spent (the scan goes on with the next).
func endsCheck(err error) bool {
	return IsFatal(err) || errors.Is(err, active.ErrModuleBudget)
}

// send wraps Client.Send: an error that does not end the check (one request
// refused or failed) returns nil, nil so the check moves on.
func send(ctx context.Context, c *active.Client, r active.Request) (*active.Response, error) {
	resp, err := c.Send(ctx, r)
	if err != nil && endsCheck(err) {
		return nil, err
	}
	return resp, nil
}

// send for a check: as consented account A when the customer gave one (discovery found the
// points logged in, so they must be tested logged in too: anonymously they only redirect to
// the login page), anonymous otherwise. IDOR sends its anonymous and account-B requests itself.
func (e Env) send(ctx context.Context, r active.Request) (*active.Response, error) {
	return send(ctx, e.Client, active.AsSession(r, e.SessionA))
}

// ---- reflected XSS ----

// XSS: an inert marker element or attribute that the browser's HTML parser
// would build from the reflected parameter (checked with the same parser).
type XSS struct{}

// ID implements Check.
func (XSS) ID() string { return evidence.CheckActiveXss }

// Run implements Check.
func (c XSS) Run(ctx context.Context, env Env) ([]evidence.Finding, error) {
	var out []evidence.Finding
	for _, pt := range env.Points {
		for _, pid := range []string{"xss.marker.tag", "xss.marker.attr", "xss.marker.attr1"} {
			resp, err := env.send(ctx, active.Probe(c.ID(), pt.URL, pt.Param, payload(pid)))
			if err != nil {
				return out, err
			}
			if resp == nil || !isHTML(resp) {
				continue
			}
			ctxName := parsedMarker(resp.Body)
			if ctxName == "" {
				continue
			}
			out = append(out, evidence.New(c.ID(), "reflected_xss",
				map[string]string{"path": pt.URL.Path, "param": pt.Param, "context": ctxName},
				evidence.KindHttpResponse, pt.URL.Scheme+"://"+pt.URL.Host+pt.URL.Path+"?"+pt.Param,
				fmt.Sprintf("GET %s with %s=<marker %s> -> HTTP %d; the HTML parser builds the marker (%s): '<', '>' and '\"' are not encoded",
					pt.URL.Path, pt.Param, pid, resp.Status, ctxName)))
			break
		}
	}
	return out, nil
}

// parsedMarker returns "element" or "attribute" when the page parses into
// the marker element <ghx7 data-gh=1> or an element with data-gh7a="1".
func parsedMarker(body []byte) string {
	z := htmlx.NewTokenizer(bytes.NewReader(body))
	for {
		tt := z.Next()
		if tt == htmlx.ErrorToken {
			return ""
		}
		if tt != htmlx.StartTagToken && tt != htmlx.SelfClosingTagToken {
			continue
		}
		tok := z.Token()
		for _, a := range tok.Attr {
			if tok.Data == "ghx7" && a.Key == "data-gh" && a.Val == "1" {
				return "element"
			}
			if a.Key == "data-gh7a" && a.Val == "1" {
				return "attribute"
			}
		}
	}
}

// ---- SQL injection ----

// SQLi: error-based (a quote causes a database error its harmless doubled
// form does not) or boolean-based (a true condition answers like itself
// twice and unlike the false one). Read-only payloads; no delays.
type SQLi struct{}

// ID implements Check.
func (SQLi) ID() string { return evidence.CheckActiveSqli }

var sqlErrorRe = regexp.MustCompile(`(?i)(you have an error in your sql syntax|warning: mysqli?_|mysql_fetch|SQLSTATE\[|SQLITE_ERROR|sqlite3?\.OperationalError|unrecognized token:|near "[^"]*": syntax error|unterminated quoted string|pg_query\(\)|syntax error at or near|ORA-0\d{4}|unclosed quotation mark|incorrect syntax near|quoted string not properly terminated|SequelizeDatabaseError)`)

// Run implements Check.
func (c SQLi) Run(ctx context.Context, env Env) ([]evidence.Finding, error) {
	var out []evidence.Finding
	for _, pt := range env.Points {
		tech, why, err := c.point(ctx, env, pt)
		if err != nil {
			return out, err
		}
		if tech == "" {
			continue
		}
		out = append(out, evidence.New(c.ID(), "sql_injection",
			map[string]string{"path": pt.URL.Path, "param": pt.Param, "technique": tech},
			evidence.KindHttpResponse, pt.URL.Scheme+"://"+pt.URL.Host+pt.URL.Path+"?"+pt.Param, why))
	}
	return out, nil
}

func (c SQLi) point(ctx context.Context, env Env, pt Point) (string, string, error) {
	base, err := env.send(ctx, active.Baseline(c.ID(), pt.URL))
	if err != nil || base == nil {
		return "", "", err
	}
	q := payload("sqli.quote")
	r, err := env.send(ctx, active.Probe(c.ID(), pt.URL, pt.Param, q))
	if err != nil || r == nil {
		return "", "", err
	}
	if m := sqlErrorRe.Find(r.Body); m != nil && !sqlErrorRe.Match(base.Body) {
		ctl, err := env.send(ctx, active.ControlProbe(c.ID(), pt.URL, pt.Param, q))
		if err != nil {
			return "", "", err
		}
		if ctl != nil && !sqlErrorRe.Match(ctl.Body) {
			return "error", fmt.Sprintf("GET %s with %s=%s -> HTTP %d with a database error (%q); the same-length harmless value %s -> HTTP %d without it",
				pt.URL.Path, pt.Param, q.Value, r.Status, evidence.Truncate(string(m), 80), q.Control, ctl.Status), nil
		}
	}
	// The conditions follow the parameter's own value ("3 AND 7=7" for a page linked with 3),
	// so the true condition keeps the page's row; active.Probe fills it in (anchor.go).
	for _, pid := range []string{"sqli.bool.orig", "sqli.bool.num.orig"} {
		p := payload(pid)
		tr, fr := active.Probe(c.ID(), pt.URL, pt.Param, p), active.ControlProbe(c.ID(), pt.URL, pt.Param, p)
		t1, err := env.send(ctx, tr)
		if err != nil || t1 == nil {
			return "", "", err
		}
		f, err := env.send(ctx, fr)
		if err != nil || f == nil {
			return "", "", err
		}
		strip := []string{tr.Sent(), fr.Sent()}
		// "the same answer" = same status AND the same words: a page that says 200 "found" for
		// the true condition and 404 "missing" for the false one differs even when both bodies
		// are nearly identical (DVWA sqli_blind). The true condition must answer like the
		// original request, so a page that merely varies with any input is not reported.
		same := func(a, b *active.Response) bool { return a.Status == b.Status && similar(a.Body, b.Body, strip) }
		if t1.Status != 200 || same(t1, f) || !same(t1, base) {
			continue
		}
		t2, err := env.send(ctx, tr)
		if err != nil || t2 == nil {
			return "", "", err
		}
		f2, err := env.send(ctx, fr)
		if err != nil || f2 == nil {
			return "", "", err
		}
		if same(t1, t2) && same(f, f2) && !same(t2, f2) {
			return "boolean", fmt.Sprintf("GET %s: %s=%s (true: HTTP %d, %d bytes, like the original) and %s (false: HTTP %d, %d bytes) answer differently, each the same when repeated",
				pt.URL.Path, pt.Param, tr.Sent(), t1.Status, len(t1.Body), fr.Sent(), f.Status, len(f.Body)), nil
		}
	}
	return "", "", nil
}

var wordRe = regexp.MustCompile(`[A-Za-z0-9]+`)

// similar compares two bodies as word sets, after removing the given
// strings (and their HTML- and URL-encoded forms): Jaccard >= 0.95.
func similar(a, b []byte, strip []string) bool {
	clean := func(x []byte) map[string]bool {
		s := string(x)
		for _, v := range strip {
			for _, form := range []string{v, html.EscapeString(v), url.QueryEscape(v), strings.ReplaceAll(html.EscapeString(v), "&#39;", "&#x27;")} {
				if form != "" {
					s = strings.ReplaceAll(s, form, " ")
				}
			}
		}
		set := map[string]bool{}
		for _, w := range wordRe.FindAllString(s, -1) {
			set[w] = true
		}
		return set
	}
	sa, sb := clean(a), clean(b)
	if len(sa) == 0 && len(sb) == 0 {
		return true
	}
	inter := 0
	for w := range sa {
		if sb[w] {
			inter++
		}
	}
	union := len(sa) + len(sb) - inter
	return float64(inter)/float64(union) >= 0.95
}

// ---- open redirect ----

// Redirect: the parameter sends the browser to GuardHub's canary host
// (never resolvable, never followed).
type Redirect struct{}

// ID implements Check.
func (Redirect) ID() string { return evidence.CheckActiveRedirect }

// Run implements Check.
func (c Redirect) Run(ctx context.Context, env Env) ([]evidence.Finding, error) {
	var out []evidence.Finding
	for _, pt := range env.Points {
		for _, pid := range []string{"redirect.canary.abs", "redirect.canary.proto"} {
			resp, err := env.send(ctx, active.Probe(c.ID(), pt.URL, pt.Param, payload(pid)))
			if err != nil {
				return out, err
			}
			if resp == nil || !redirectsToCanary(resp) {
				continue
			}
			out = append(out, evidence.New(c.ID(), "open_redirect",
				map[string]string{"path": pt.URL.Path, "param": pt.Param},
				evidence.KindHttpResponse, pt.URL.Scheme+"://"+pt.URL.Host+pt.URL.Path+"?"+pt.Param,
				fmt.Sprintf("GET %s with %s=%s -> HTTP %d, Location: %s (GuardHub's canary host; not followed)",
					pt.URL.Path, pt.Param, payload(pid).Value, resp.Status, evidence.Truncate(resp.Location, 200))))
			break
		}
	}
	return out, nil
}

func redirectsToCanary(r *active.Response) bool {
	loc := r.Location
	if loc == "" {
		if ref := r.Header.Get("Refresh"); ref != "" {
			if i := strings.Index(strings.ToLower(ref), "url="); i >= 0 {
				loc = strings.Trim(strings.TrimSpace(ref[i+4:]), `'"`)
			}
		}
	}
	if loc == "" {
		return false
	}
	u, err := r.URL.Parse(strings.TrimSpace(loc))
	return err == nil && strings.EqualFold(u.Hostname(), active.CanaryHost)
}

// ---- CORS ----

// CORS: a discovered endpoint (not the home page: http_hardening covers it)
// grants a foreign origin credentialed access by echoing it.
type CORS struct{}

// ID implements Check.
func (CORS) ID() string { return evidence.CheckActiveCors }

// Run implements Check.
func (c CORS) Run(ctx context.Context, env Env) ([]evidence.Finding, error) {
	var out []evidence.Finding
	done := map[string]bool{"/": true}
	for _, pg := range env.Pages {
		if done[pg.URL.Path] || len(out) >= 3 {
			continue
		}
		done[pg.URL.Path] = true
		for _, pid := range []string{"cors.canary.origin", "cors.null.origin"} {
			p := payload(pid)
			resp, err := env.send(ctx, active.Probe(c.ID(), pg.URL, "", p))
			if err != nil {
				return out, err
			}
			if resp == nil {
				continue
			}
			acao := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin"))
			// the Fetch standard's CORS check compares both values byte for byte: a browser
			// refuses a credentialed read for "True" or "TRUE", so only exactly "true" counts
			if acao == p.Value && strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials")) == "true" {
				out = append(out, evidence.New(c.ID(), "cors_origin_reflected",
					map[string]string{"path": pg.URL.Path, "origin": p.Value},
					evidence.KindHttpHeader, pg.URL.Scheme+"://"+pg.URL.Host+pg.URL.Path,
					fmt.Sprintf("GET %s with Origin: %s -> Access-Control-Allow-Origin: %s, Access-Control-Allow-Credentials: true",
						pg.URL.Path, p.Value, acao)))
				break
			}
		}
	}
	return out, nil
}

// ---- SSRF ----

// SSRF: a URL-taking parameter makes the server fetch GuardHub's
// collaborator URL (out of band, unique token per probe).
type SSRF struct{}

// ID implements Check.
func (SSRF) ID() string { return evidence.CheckActiveSsrf }

var urlParamRe = regexp.MustCompile(`(?i)^(url|uri|link|href|src|source|dest|destination|target|image|img|feed|fetch|file|path|callback|webhook|proxy|load|remote|site|domain|host|redirect|next|return|continue|page|doc|document|reference|ref|data)(_?url)?$`)

// Run implements Check.
func (c SSRF) Run(ctx context.Context, env Env) ([]evidence.Finding, error) {
	if env.Collab == nil {
		return nil, nil
	}
	wait := env.OOBWait
	if wait <= 0 {
		wait = 5 * time.Second
	}
	var out []evidence.Finding
	p := payload("ssrf.oob.http")
	for _, pt := range env.Points {
		v := pt.URL.Query().Get(pt.Param)
		if !urlParamRe.MatchString(pt.Param) && !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") {
			continue
		}
		tok := active.NewToken()
		if _, err := env.send(ctx, active.OOBProbe(c.ID(), pt.URL, pt.Param, p, env.Collab.URL(tok))); err != nil {
			return out, err
		}
		seen, err := active.WaitSeen(ctx, env.Collab, tok, wait, 250*time.Millisecond)
		if err != nil || !seen {
			continue
		}
		out = append(out, evidence.New(c.ID(), "ssrf_confirmed",
			map[string]string{"path": pt.URL.Path, "param": pt.Param},
			evidence.KindHttpResponse, pt.URL.Scheme+"://"+pt.URL.Host+pt.URL.Path+"?"+pt.Param,
			fmt.Sprintf("GET %s with %s set to GuardHub's collaborator URL -> the server itself fetched it (confirmed out of band)",
				pt.URL.Path, pt.Param)))
	}
	return out, nil
}
