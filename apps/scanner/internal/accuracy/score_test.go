package accuracy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
)

func finding(check, key, loc string) evidence.Finding {
	return evidence.New(check, key, map[string]string{}, evidence.KindHttpResponse, loc, "x")
}

func TestScoreCountsTPFPFNToleratedAndErrors(t *testing.T) {
	ms := []Manifest{
		{
			Target: "vuln", Origin: "http://vuln", Checks: []string{"security_headers", "info_leak"},
			Expect: []Expectation{
				{Check: "security_headers", Key: "csp_missing", Why: "no CSP configured"},
				{Check: "security_headers", Key: "hsts_missing", Why: "no HSTS configured"},
				{Check: "info_leak", Key: "directory_listing_enabled", Location: "http://vuln/ftp", Why: "autoindex on /ftp"},
			},
			Tolerate: []Expectation{{Check: "info_leak", Key: "server_version_disclosed", Why: "debatable"}},
		},
		{Target: "clean", Origin: "http://clean", Checks: []string{"security_headers", "info_leak"}},
		{Target: "down", Origin: "http://down", Checks: []string{"info_leak"},
			Expect: []Expectation{{Check: "info_leak", Key: "stack_trace_exposed", Why: "500 page with trace"}}},
	}
	runs := []TargetRun{
		{Target: "vuln", Findings: []evidence.Finding{
			finding("security_headers", "csp_missing", "http://vuln/"),
			finding("security_headers", "nosniff_missing", "http://vuln/"),         // FP
			finding("info_leak", "directory_listing_enabled", "http://vuln/other"), // wrong location: FP + FN
			finding("info_leak", "server_version_disclosed", "http://vuln/"),       // tolerated
		}},
		{Target: "clean", Findings: []evidence.Finding{finding("info_leak", "server_version_disclosed", "http://clean/")}}, // FP: not tolerated here
		{Target: "down", Failed: map[string]string{"info_leak": "target_unreachable"}},
	}
	scores := Score(ms, runs)
	if len(scores) != 2 || scores[0].CheckID != "info_leak" || scores[1].CheckID != "security_headers" {
		t.Fatalf("unexpected scores: %+v", scores)
	}
	il, sh := scores[0], scores[1]
	if sh.TP != 1 || sh.FP != 1 || sh.FN != 1 || sh.CleanRuns != 1 || sh.Errors != 0 {
		t.Errorf("security_headers: %+v", sh)
	}
	if il.TP != 0 || il.FP != 2 || il.FN != 2 || il.Tolerated != 1 || il.Errors != 1 || il.CleanRuns != 1 {
		t.Errorf("info_leak: tp=%d fp=%d fn=%d tol=%d err=%d clean=%d", il.TP, il.FP, il.FN, il.Tolerated, il.Errors, il.CleanRuns)
	}
	if *sh.Precision != 0.5 || *sh.Recall != 0.5 || sh.MeetsGate {
		t.Errorf("security_headers ratios/gate: p=%v r=%v gate=%v", *sh.Precision, *sh.Recall, sh.MeetsGate)
	}
	if il.MeetsGate || !strings.Contains(strings.Join(il.GateNotes, ","), "failed") {
		t.Errorf("a check that errored must not meet the gate: %v", il.GateNotes)
	}
	if !strings.HasPrefix(il.FalseNeg[0].Why, "check did not run") && !strings.HasPrefix(il.FalseNeg[1].Why, "check did not run") {
		t.Errorf("FN from a failed run must say so: %+v", il.FalseNeg)
	}
}

func TestGateNeedsEnoughPositivesAndACleanRun(t *testing.T) {
	ms := []Manifest{{Target: "a", Origin: "http://a", Checks: []string{"security_headers"},
		Expect: []Expectation{{Check: "security_headers", Key: "csp_missing", Why: "x"}}}}
	runs := []TargetRun{{Target: "a", Findings: []evidence.Finding{finding("security_headers", "csp_missing", "http://a/")}}}
	s := Score(ms, runs)[0]
	if s.MeetsGate || *s.Precision != 1 {
		t.Fatalf("1 positive and no clean target must not pass: %+v", s)
	}
	notes := strings.Join(s.GateNotes, ",")
	if !strings.Contains(notes, "too few") || !strings.Contains(notes, "no clean target") {
		t.Errorf("notes: %s", notes)
	}

	// enough positives on several targets plus a clean one → passes
	ms, runs = nil, nil
	for _, n := range []string{"a", "b", "c"} {
		ms = append(ms, Manifest{Target: n, Origin: "http://" + n, Checks: []string{"security_headers"},
			Expect: []Expectation{{Check: "security_headers", Key: "csp_missing", Why: "x"}}})
		runs = append(runs, TargetRun{Target: n, Findings: []evidence.Finding{finding("security_headers", "csp_missing", "http://"+n+"/")}})
	}
	ms = append(ms, Manifest{Target: "z", Origin: "http://z", Checks: []string{"security_headers"}})
	runs = append(runs, TargetRun{Target: "z"})
	if s := Score(ms, runs)[0]; !s.MeetsGate {
		t.Errorf("should pass: %+v", s)
	}
}

func TestManifestValidation(t *testing.T) {
	bad := []Manifest{
		{Target: "x", Origin: "http://x"},                           // no checks
		{Target: "x", Origin: "http://x", Checks: []string{"nope"}}, // unknown check
		{Target: "x", Origin: "http://x", Checks: []string{"info_leak"}, // no reason
			Expect: []Expectation{{Check: "info_leak", Key: "stack_trace_exposed"}}},
		{Target: "x", Origin: "http://x", Checks: []string{"info_leak"}, // unknown key
			Expect: []Expectation{{Check: "info_leak", Key: "nope", Why: "y"}}},
		{Target: "x", Origin: "http://x", Checks: []string{"info_leak"}, // expectation for an unscored check
			Expect: []Expectation{{Check: "security_headers", Key: "csp_missing", Why: "y"}}},
	}
	for i, m := range bad {
		if m.Validate() == nil {
			t.Errorf("manifest %d should be invalid", i)
		}
	}
}

func TestLoadManifestsRejectsUnknownFieldsAndWritesReports(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("a.yaml", "target: a\norigin: http://a\nchecks: [info_leak]\nexpect:\n  - {check: info_leak, key: stack_trace_exposed, why: trace on 500}\n")
	ms, err := LoadManifests(dir)
	if err != nil || len(ms) != 1 {
		t.Fatalf("load: %v %v", ms, err)
	}
	write("b.yaml", "target: b\norigin: http://b\nchecks: [info_leak]\nexpcet: []\n")
	if _, err := LoadManifests(dir); err == nil {
		t.Fatal("a typo'd field must be rejected, not silently ignored")
	}

	out := t.TempDir()
	sc := NewScorecard("abc123", ms, Score(ms, []TargetRun{{Target: "a"}}))
	if err := Write(out, sc); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"scorecard.json", "README.md", "info_leak.md"} {
		raw, err := os.ReadFile(filepath.Join(out, f))
		if err != nil || len(raw) == 0 {
			t.Fatalf("%s: %v", f, err)
		}
	}
	md, _ := os.ReadFile(filepath.Join(out, "info_leak.md"))
	if !strings.Contains(string(md), "False negatives (1)") || !strings.Contains(string(md), "trace on 500") {
		t.Errorf("detail page should list the miss with its reason:\n%s", md)
	}
}

func TestOutsideMissesLowerOnlyRecallAll(t *testing.T) {
	ms := []Manifest{{Target: "a", Origin: "http://a", Checks: []string{"default_creds"}, Expect: []Expectation{
		{Check: "default_creds", Key: "installer_exposed", Why: "in the catalogue"},
		{Check: "default_creds", Key: "default_login_product", Outside: true, Why: "product not in the catalogue"},
	}}}
	runs := []TargetRun{{Target: "a", Findings: []evidence.Finding{finding("default_creds", "installer_exposed", "http://a/x")}}}
	s := Score(ms, runs)[0]
	if s.TP != 1 || s.FN != 0 || s.FNOutside != 1 || *s.Recall != 1 || *s.RecallAll != 0.5 {
		t.Fatalf("tp=%d fn=%d out=%d recall=%v all=%v", s.TP, s.FN, s.FNOutside, *s.Recall, *s.RecallAll)
	}
	if len(s.FalseNeg) != 1 || !s.FalseNeg[0].Outside {
		t.Fatalf("the outside miss must still be listed: %+v", s.FalseNeg)
	}
}
