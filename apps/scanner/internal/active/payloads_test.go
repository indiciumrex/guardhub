package active

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var (
	sqlWrite = regexp.MustCompile(`(?i)\b(insert|update|delete|drop|truncate|alter|create|grant|revoke|exec|execute|merge|replace|call|lock|load_file|outfile|dumpfile|xp_\w*|sp_\w*)\b`)
	delay    = regexp.MustCompile(`(?i)(sleep|benchmark|pg_sleep|waitfor|delay|randomblob|generate_series)`)
	script   = regexp.MustCompile(`(?i)(<\s*script|javascript:|vbscript:|\bon[a-z]+\s*=|<\s*(img|svg|iframe|object|embed|body|style|link|meta|base|form|input|video|audio)\b|srcdoc|expression\s*\()`)
	internal = regexp.MustCompile(`(?i)(localhost|127\.|169\.254\.|\b10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|metadata|\[::|0x|file:|gopher:|dict:)`)
)

// review is the automated half of the do-no-harm payload review (ADR-0008
// §5): the problems it finds in one payload.
func review(p Payload) []string {
	var out []string
	errorf := func(f string, a ...any) { out = append(out, fmt.Sprintf(f, a...)) }
	if p.ID == "" || p.Module == "" || p.Why == "" {
		errorf("%q: id, module and why are required", p.ID)
	}
	if p.In != InQuery && p.In != InOrigin {
		errorf("%s: unknown placement %q", p.ID, p.In)
	}
	for _, v := range []string{p.Value, p.Control} {
		if len(v) > 256 {
			errorf("%s: longer than 256 bytes", p.ID)
		}
		if strings.Contains(v, ";") {
			errorf("%s: ';' (stacked statements) is not allowed: %q", p.ID, v)
		}
		if sqlWrite.MatchString(v) {
			errorf("%s: data-changing or locking SQL keyword: %q", p.ID, v)
		}
		if delay.MatchString(v) {
			errorf("%s: a delay or heavy function: %q", p.ID, v)
		}
		if script.MatchString(v) {
			errorf("%s: self-executing or loading markup: %q", p.ID, v)
		}
		if internal.MatchString(v) {
			errorf("%s: names an internal or local address or a non-http scheme: %q", p.ID, v)
		}
	}
	// any URL a payload names points at the canary or the OOB placeholder only
	for _, v := range []string{p.Value, p.Control} {
		if !strings.Contains(v, "//") {
			continue
		}
		raw := strings.ReplaceAll(v, OOBPlaceholder, "tok.oob.example")
		if strings.HasPrefix(raw, "//") {
			raw = "https:" + raw
		}
		u, err := url.Parse(raw)
		if err != nil {
			errorf("%s: unparsable URL %q", p.ID, v)
			continue
		}
		if h := u.Hostname(); h != CanaryHost && h != "tok.oob.example" {
			errorf("%s: names host %q (only %s or the OOB placeholder)", p.ID, h, CanaryHost)
		}
		if strings.Contains(v, OOBPlaceholder) && !strings.HasPrefix(v, "http://"+OOBPlaceholder) {
			errorf("%s: the OOB placeholder must be the whole host", p.ID)
		}
	}
	return out
}

// TestPayloadsDoNoHarm runs the review on the whole catalogue (CI, every change).
func TestPayloadsDoNoHarm(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range Payloads {
		if seen[p.ID] {
			t.Errorf("duplicate payload id %s", p.ID)
		}
		seen[p.ID] = true
		for _, problem := range review(p) {
			t.Error(problem)
		}
	}
}

// TestReviewRulesCatchHarmful proves the rules above reject what they must.
func TestReviewRulesCatchHarmful(t *testing.T) {
	bad := []Payload{
		{ID: "a", Module: "m", In: InQuery, Why: "x", Value: "1'; DROP TABLE users--"},
		{ID: "b", Module: "m", In: InQuery, Why: "x", Value: "1' AND SLEEP(5)--"},
		{ID: "c", Module: "m", In: InQuery, Why: "x", Value: "<script>alert(1)</script>"},
		{ID: "d", Module: "m", In: InQuery, Why: "x", Value: "<img src=x onerror=alert(1)>"},
		{ID: "e", Module: "m", In: InQuery, Why: "x", Value: "http://169.254.169.254/latest/meta-data/"},
		{ID: "f", Module: "m", In: InQuery, Why: "x", Value: "https://evil.example/"},
		{ID: "g", Module: "m", In: InQuery, Why: "x", Value: "1 UNION SELECT 1 INTO OUTFILE '/tmp/x'"},
	}
	for _, b := range bad {
		if len(review(b)) == 0 {
			t.Errorf("the review rules accepted %q", b.Value)
		}
	}
}
