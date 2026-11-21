package deps

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func rec(id string, eco, name string, events ...map[string]string) *Vuln {
	v := &Vuln{ID: id}
	a := Affected{Ranges: []Range{{Type: "ECOSYSTEM", Events: events}}}
	a.Package.Ecosystem, a.Package.Name = eco, name
	v.Affected = []Affected{a}
	return v
}

func ev(k, v string) map[string]string { return map[string]string{k: v} }

func TestRangePlacementPicksTheContainingInterval(t *testing.T) {
	// Two affected intervals: [0, 1.2.6) and [2.0.0, 2.0.3) (unsorted on purpose).
	r := rec("GHSA-x", EcosystemNPM, "minimist", ev("introduced", "2.0.0"), ev("fixed", "2.0.3"), ev("introduced", "0"), ev("fixed", "1.2.6"))
	cases := map[string]string{"1.2.5": "1.2.6", "0.0.8": "1.2.6", "2.0.1": "2.0.3"}
	for version, want := range cases {
		got, ok := fixedVersion(Package{Ecosystem: EcosystemNPM, Name: "minimist", Version: version}, r)
		if !ok || got != want {
			t.Errorf("%s: fix %q ok=%v, want %q", version, got, ok, want)
		}
	}
	// last_affected: affected, no fix known.
	r2 := rec("GHSA-y", EcosystemPyPI, "Some_Pkg", ev("introduced", "1.0"), ev("last_affected", "1.4"))
	if f, ok := fixedVersion(Package{Ecosystem: EcosystemPyPI, Name: "some-pkg", Version: "1.4"}, r2); ok {
		t.Errorf("last_affected must give no fix, got %q", f)
	}
	// Version OSV matched through an explicit list (outside our ranges): the lowest fix above it.
	r3 := rec("PYSEC-1", EcosystemPyPI, "django", ev("introduced", "4.0"), ev("fixed", "4.0.2"), ev("introduced", "3.2"), ev("fixed", "3.2.12"))
	if f, ok := fixedVersion(Package{Ecosystem: EcosystemPyPI, Name: "Django", Version: "3.1.0"}, r3); !ok || f != "3.2.12" {
		t.Errorf("fallback fix %q ok=%v", f, ok)
	}
	// Another package's ranges never count.
	if _, ok := fixedVersion(Package{Ecosystem: EcosystemNPM, Name: "lodash", Version: "1.0.0"}, r); ok {
		t.Error("ranges of another package must not apply")
	}
}

func TestAssessGroupsAliasesAndPicksFix(t *testing.T) {
	pkg := Package{Ecosystem: EcosystemPyPI, Name: "pyyaml", Version: "5.3"}
	ghsa := rec("GHSA-8q59-q68h-6hv4", EcosystemPyPI, "PyYAML", ev("introduced", "0"), ev("fixed", "5.4"))
	ghsa.Aliases = []string{"CVE-2020-14343"}
	ghsa.DatabaseSpecific.Severity = "CRITICAL"
	pysec := rec("PYSEC-2021-142", EcosystemPyPI, "pyyaml", ev("introduced", "0"), ev("fixed", "5.4"))
	pysec.Aliases = []string{"CVE-2020-14343", "GHSA-8q59-q68h-6hv4"}
	low := rec("GHSA-low", EcosystemPyPI, "pyyaml", ev("introduced", "0"), ev("fixed", "5.3.1"))
	low.DatabaseSpecific.Severity = "LOW"
	withdrawn := rec("GHSA-gone", EcosystemPyPI, "pyyaml", ev("introduced", "0"), ev("fixed", "9.0"))
	withdrawn.Withdrawn = "2021-01-01T00:00:00Z"

	v, ok := Assess(pkg, []*Vuln{ghsa, pysec, low, withdrawn})
	if !ok {
		t.Fatal("expected a verdict")
	}
	if got := v.IDs(); !reflect.DeepEqual(got, []string{"CVE-2020-14343", "GHSA-low"}) {
		t.Errorf("ids = %v", got)
	}
	if v.Fixed != "5.4" || v.Unfixed != 0 || v.MaxRating() != RatingCritical {
		t.Errorf("verdict = %+v", v)
	}
	if _, ok := Assess(pkg, []*Vuln{withdrawn}); ok {
		t.Error("only withdrawn advisories: no verdict")
	}
}

func TestRatingFallsBackToCVSS(t *testing.T) {
	r := &Vuln{ID: "PYSEC-1", Severity: []Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}}
	if rating(r) != RatingHigh {
		t.Errorf("CVSS 7.5 must rate high, got %v", rating(r))
	}
	r.DatabaseSpecific.Severity = "MODERATE"
	if rating(r) != RatingModerate {
		t.Error("the GitHub Advisory rating wins over CVSS")
	}
	if rating(&Vuln{ID: "X"}) != RatingUnrated {
		t.Error("no data: unrated")
	}
}

func TestGitHubRatingWinsOverAnAliasVector(t *testing.T) {
	// CVE-2024-56326 (jinja2): GitHub rates it MODERATE; the PYSEC alias only has
	// a local-attack CVSS vector that scores 7.8. The issue is MODERATE.
	ghsa := rec("GHSA-q2x7-8rv6-6q7h", EcosystemPyPI, "jinja2", ev("introduced", "0"), ev("fixed", "3.1.5"))
	ghsa.Aliases = []string{"CVE-2024-56326", "PYSEC-2026-1475"}
	ghsa.DatabaseSpecific.Severity = "MODERATE"
	pysec := rec("PYSEC-2026-1475", EcosystemPyPI, "jinja2", ev("introduced", "0"), ev("fixed", "3.1.5"))
	pysec.Aliases = []string{"CVE-2024-56326", "GHSA-q2x7-8rv6-6q7h"}
	pysec.Severity = []Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}}
	v, ok := Assess(Package{Ecosystem: EcosystemPyPI, Name: "jinja2", Version: "2.11.2"}, []*Vuln{ghsa, pysec})
	if !ok || v.MaxRating() != RatingModerate {
		t.Fatalf("rating %v, want MODERATE", v.MaxRating())
	}
	// Without any GitHub rating in the group, the vector decides.
	v, _ = Assess(Package{Ecosystem: EcosystemPyPI, Name: "jinja2", Version: "2.11.2"}, []*Vuln{pysec})
	if v.MaxRating() != RatingHigh {
		t.Fatalf("CVSS-only group: rating %v, want HIGH", v.MaxRating())
	}
}

func TestMaliciousRecord(t *testing.T) {
	v, ok := Assess(Package{Ecosystem: EcosystemNPM, Name: "evil", Version: "1.0.0"},
		[]*Vuln{rec("MAL-2024-1", EcosystemNPM, "evil", ev("introduced", "0"))})
	if !ok || !v.Malicious() || v.Fixed != "" || v.Unfixed != 1 {
		t.Errorf("verdict = %+v", v)
	}
}

// --------------------------------------------------------------- OSV client

func TestOSVMatchesPagingAndVulns(t *testing.T) {
	var fails atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasPrefix(r.Header.Get("User-Agent"), "GuardHub-Scanner/") {
			http.Error(w, "bad", 400)
			return
		}
		if fails.Add(1) == 1 {
			http.Error(w, "busy", http.StatusServiceUnavailable) // one transient failure: retried
			return
		}
		var body struct {
			Queries []osvQuery `json:"queries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		type vuln struct {
			ID string `json:"id"`
		}
		type result struct {
			Vulns         []vuln `json:"vulns,omitempty"`
			NextPageToken string `json:"next_page_token,omitempty"`
		}
		var out struct {
			Results []result `json:"results"`
		}
		for _, q := range body.Queries {
			switch {
			case q.Package.Name == "lodash" && q.PageToken == "":
				out.Results = append(out.Results, result{Vulns: []vuln{{"GHSA-1"}}, NextPageToken: "p2"})
			case q.Package.Name == "lodash" && q.PageToken == "p2":
				out.Results = append(out.Results, result{Vulns: []vuln{{"GHSA-2"}, {"bad id with spaces"}}})
			default:
				out.Results = append(out.Results, result{})
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/v1/vulns/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	o := NewOSV(srv.URL, http.DefaultTransport, 5*time.Second, 1)
	pkgs := []Package{{Ecosystem: EcosystemNPM, Name: "lodash", Version: "4.17.15"}, {Ecosystem: EcosystemNPM, Name: "clean", Version: "1.0.0"}}
	m, err := o.Matches(context.Background(), pkgs)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m[0], []string{"GHSA-1", "GHSA-2"}) || len(m[1]) != 0 {
		t.Fatalf("matches = %v", m)
	}
	recs, err := o.Vulns(context.Background(), []string{"GHSA-1", "GHSA-1", "GHSA-2"})
	if err == nil || len(recs) != 1 {
		t.Fatalf("cap of 1 must cut with ErrTooManyAdvisories: %v %v", recs, err)
	}
}

func TestOSVDownIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer srv.Close()
	o := NewOSV(srv.URL, http.DefaultTransport, 5*time.Second, 10)
	_, err := o.Matches(context.Background(), []Package{{Ecosystem: EcosystemNPM, Name: "x", Version: "1.0.0"}})
	if err == nil || !strings.Contains(err.Error(), "OSV") {
		t.Fatalf("err = %v", err)
	}
}
