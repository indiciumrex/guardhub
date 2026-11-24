package activescan

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/hksolutions/guardhub/apps/scanner/internal/active"
	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
)

// ---- IDOR (insecure direct object reference) ----

// IDOR: account B reads an object that belongs to account A by its
// identifier. It needs two consented test accounts of the customer
// (Env.SessionA/SessionB, ADR-0008 §5) and is silent without them: guessing
// neighbouring ids anonymously cannot tell a private object from a public
// one, so it would not meet the precision gate.
//
// Only unmodified GETs are sent (no payload): A's pages are discovered as A;
// a page whose URL names an object (id-like parameter or numeric/UUID path
// segment) and shows A's marker is then requested anonymously and as B. It is
// reported when B gets HTTP 200 with A's marker and essentially A's content,
// while an anonymous request does not see A's marker (the object is not
// public). Pages that look state-changing are never requested (unsafeLink).
type IDOR struct{}

// ID implements Check.
func (IDOR) ID() string { return evidence.CheckActiveIdor }

var (
	idParamRe = regexp.MustCompile(`(?i)^(id|uid|gid|pid|oid|key|ref|no|num|number|[a-z]+[_-]?(id|no|num|number|key|ref))$`)
	idValueRe = regexp.MustCompile(`(?i)^([0-9]{1,12}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24})$`)
)

// idorMaxObjects bounds the objects tried per scan (each costs 2 requests).
const idorMaxObjects = 15

// namesObject reports whether u identifies an object: an id-like query
// parameter with an id-like value, or a numeric/UUID path segment.
func namesObject(u *url.URL) (string, bool) {
	for k, vs := range u.Query() {
		if idParamRe.MatchString(k) && len(vs) > 0 && idValueRe.MatchString(vs[0]) {
			return k, true
		}
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg != "" && idValueRe.MatchString(seg) {
			return "path", true
		}
	}
	return "", false
}

// Run implements Check.
func (c IDOR) Run(ctx context.Context, env Env) ([]evidence.Finding, error) {
	a, b := env.SessionA, env.SessionB
	if a == nil || b == nil || a.Validate() != nil || b.Validate() != nil || a.Marker == b.Marker {
		return nil, nil
	}
	_, pages, err := DiscoverAs(ctx, env.Client, env.Origin, env.Start, DiscoveryLimits{}, a)
	if err != nil && IsFatal(err) {
		return nil, err
	}
	markA, markB := []byte(a.Marker), []byte(b.Marker)
	var out []evidence.Finding
	tried := 0
	for _, pg := range pages {
		if tried >= idorMaxObjects {
			break
		}
		param, ok := namesObject(pg.URL)
		// an object that already names B on A's own view is shared between them: not tried
		if !ok || pg.Resp.Status != 200 || !bytes.Contains(pg.Resp.Body, markA) || bytes.Contains(pg.Resp.Body, markB) || unsafeLink(pg.URL) {
			continue
		}
		tried++
		anon, err := send(ctx, env.Client, active.Baseline(c.ID(), pg.URL))
		if err != nil {
			return out, err
		}
		if anon != nil && anon.Status == 200 && bytes.Contains(anon.Body, markA) {
			continue // public object: anyone may read it
		}
		asB, err := send(ctx, env.Client, active.AsSession(active.Baseline(c.ID(), pg.URL), b))
		if err != nil {
			return out, err
		}
		if asB == nil || asB.Status != 200 || !bytes.Contains(asB.Body, markA) {
			continue
		}
		// B's own navigation (its marker) aside, B must see A's object itself
		if !similar(pg.Resp.Body, asB.Body, []string{a.Marker, b.Marker}) {
			continue
		}
		anonStatus := "no answer"
		if anon != nil {
			anonStatus = fmt.Sprintf("HTTP %d without account A's marker", anon.Status)
		}
		out = append(out, evidence.New(c.ID(), "idor_cross_account_read",
			map[string]string{"path": pg.URL.Path, "param": param},
			evidence.KindHttpResponse, pg.URL.Scheme+"://"+pg.URL.Host+pg.URL.Path,
			fmt.Sprintf("GET %s as test account B -> HTTP 200 showing test account A's object (A's marker present); anonymous GET -> %s",
				pg.URL.Path, anonStatus)))
	}
	return out, nil
}
