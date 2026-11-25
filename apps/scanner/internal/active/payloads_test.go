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
	// an OOB payload is exactly the placeholder; any other URL names the canary only
	if strings.Contains(p.Value+p.Control, OOBPlaceholder) && (p.Value != OOBPlaceholder || p.Control != "") {
		errorf("%s: an OOB payload is exactly %s, with no control", p.ID, OOBPlaceholder)
	}
	for _, v := range []string{p.Value, p.Control} {
		if !strings.Contains(v, "//") {
			continue
		}
		raw := v
		if strings.HasPrefix(raw, "//") {
			raw = "https:" + raw
		}
		u, err := url.Parse(raw)
		if err != nil {
			errorf("%s: unparsable URL %q", p.ID, v)
			continue
		}
		if h := u.Hostname(); h != CanaryHost {
			errorf("%s: names host %q (only %s, or the OOB placeholder)", p.ID, h, CanaryHost)
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
		// an anchored payload is reviewed as it is sent: with the fallback and with the
		// longest anchor of its shape (the shape admits no syntax, TestAnchorShapes)
		if strings.Contains(p.Value+p.Control, OrigPlaceholder) {
			if p.Anchor != AnchorNumber && p.Anchor != AnchorWord {
				t.Errorf("%s: uses %s without an anchor shape", p.ID, OrigPlaceholder)
			}
			for _, a := range []string{AnchorFallback, strings.Repeat("9", 18), strings.Repeat("a", 64)} {
				r := p
				r.Value = strings.ReplaceAll(p.Value, OrigPlaceholder, a)
				r.Control = strings.ReplaceAll(p.Control, OrigPlaceholder, a)
				for _, problem := range review(r) {
					t.Error(problem)
				}
			}
		}
	}
}

// TestAnchorShapes: {orig} is the parameter's own value only when it has the
// payload's shape; quotes, spaces, semicolons, parentheses, comments and
// anything long fall back to 1, so the sent text is the reviewed text around
// one literal operand.
func TestAnchorShapes(t *testing.T) {
	cases := []struct {
		kind, raw, want string
	}{
		{AnchorNumber, "id=3", "3"},
		{AnchorNumber, "id=0042", "0042"},
		{AnchorNumber, "id=abc", "1"},
		{AnchorNumber, "id=3%20OR%201", "1"},
		{AnchorNumber, "id=-3", "1"},
		{AnchorNumber, "id=" + strings.Repeat("9", 19), "1"},
		{AnchorNumber, "other=3", "1"},
		{AnchorNumber, "id=", "1"},
		{AnchorWord, "id=bo@av-sqli2.lab.test", "bo@av-sqli2.lab.test"},
		{AnchorWord, "id=hello-world_2", "hello-world_2"},
		{AnchorWord, "id=a'b", "1"},
		{AnchorWord, "id=a%22b", "1"},
		{AnchorWord, "id=a%20b", "1"},
		{AnchorWord, "id=a;b", "1"},
		{AnchorWord, "id=sleep(5)", "1"},
		{AnchorWord, "id=a--", "1"},
		{AnchorWord, "id=a/*", "1"},
		{AnchorWord, "id=" + strings.Repeat("a", 65), "1"},
		{"", "id=3", "1"},
	}
	for _, c := range cases {
		u, _ := url.Parse("https://example.test/p?" + c.raw)
		if got := anchor(c.kind, u, "id"); got != c.want {
			t.Errorf("anchor(%q, %q) = %q, want %q", c.kind, c.raw, got, c.want)
		}
	}
	p, _ := PayloadByID("sqli.bool.num.orig")
	u, _ := url.Parse("https://example.test/review?id=3&x=y")
	if got := Probe("active_sqli", u, "id", p).url().Query().Get("id"); got != "3 AND 7=7" {
		t.Errorf("probe sends id=%q, want %q", got, "3 AND 7=7")
	}
	if got := ControlProbe("active_sqli", u, "id", p).Sent(); got != "3 AND 7=8" {
		t.Errorf("control sends %q, want %q", got, "3 AND 7=8")
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
