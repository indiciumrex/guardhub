package checks

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hksolutions/guardhub/apps/scanner/internal/deps"
	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/repo"
)

// fakeOSV answers querybatch from byPkg ("eco|name|version" → ids) and
// /v1/vulns from records.
func fakeOSV(t *testing.T, byPkg map[string][]string, records map[string]map[string]any) *deps.OSV {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Queries []struct {
				Package struct{ Name, Ecosystem string } `json:"package"`
				Version string                           `json:"version"`
			} `json:"queries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		type v struct {
			ID string `json:"id"`
		}
		type res struct {
			Vulns []v `json:"vulns,omitempty"`
		}
		out := struct {
			Results []res `json:"results"`
		}{}
		for _, q := range body.Queries {
			var rr res
			for _, id := range byPkg[q.Package.Ecosystem+"|"+q.Package.Name+"|"+q.Version] {
				rr.Vulns = append(rr.Vulns, v{id})
			}
			out.Results = append(out.Results, rr)
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, r *http.Request) {
		rec, ok := records[r.PathValue("id")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(rec)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return deps.NewOSV(srv.URL, http.DefaultTransport, 5*time.Second, 50)
}

func osvRecord(id, eco, name, severity string, fixed string, aliases ...string) map[string]any {
	events := []map[string]string{{"introduced": "0"}}
	if fixed != "" {
		events = append(events, map[string]string{"fixed": fixed})
	}
	rec := map[string]any{
		"id": id, "aliases": aliases,
		"affected": []any{map[string]any{
			"package": map[string]string{"ecosystem": eco, "name": name},
			"ranges":  []any{map[string]any{"type": "ECOSYSTEM", "events": events}},
		}},
	}
	if severity != "" {
		rec["database_specific"] = map[string]string{"severity": severity}
	}
	return rec
}

func depSnapshot(files map[string]string) *repo.Snapshot {
	s := &repo.Snapshot{Repo: "acme/shop", Commit: "0123456789abcdef0123456789abcdef01234567"}
	for p, d := range files {
		s.Files = append(s.Files, repo.File{Path: p, Data: []byte(d)})
	}
	return s
}

func TestDependencyVulnsKeysAndFixes(t *testing.T) {
	lock := `{"lockfileVersion":3,"packages":{
	  "node_modules/lodash":{"version":"4.17.15"},
	  "node_modules/minimist":{"version":"1.2.5"},
	  "node_modules/mocha":{"version":"8.0.0","dev":true},
	  "node_modules/left-pad":{"version":"1.0.0"},
	  "node_modules/tiny":{"version":"1.0.0"},
	  "node_modules/safe":{"version":"9.9.9"},
	  "node_modules/evil":{"version":"0.0.1","dev":true}
	}}`
	osv := fakeOSV(t, map[string][]string{
		"npm|lodash|4.17.15": {"GHSA-high", "GHSA-mod"},
		"npm|minimist|1.2.5": {"GHSA-unrated"},
		"npm|mocha|8.0.0":    {"GHSA-crit"},
		"npm|left-pad|1.0.0": {"GHSA-nofix"},
		"npm|tiny|1.0.0":     {"GHSA-low"},
		"npm|evil|0.0.1":     {"MAL-2024-1"},
		"PyPI|django|3.2.0":  {"GHSA-dj", "PYSEC-dj"},
		"PyPI|withdrawn|1.0": {"GHSA-w"},
	}, map[string]map[string]any{
		"GHSA-high":    osvRecord("GHSA-high", "npm", "lodash", "HIGH", "4.17.21", "CVE-2021-23337"),
		"GHSA-mod":     osvRecord("GHSA-mod", "npm", "lodash", "MODERATE", "4.17.19"),
		"GHSA-unrated": osvRecord("GHSA-unrated", "npm", "minimist", "", "1.2.6"),
		"GHSA-crit":    osvRecord("GHSA-crit", "npm", "mocha", "CRITICAL", "10.1.0"),
		"GHSA-nofix":   osvRecord("GHSA-nofix", "npm", "left-pad", "HIGH", ""),
		"GHSA-low":     osvRecord("GHSA-low", "npm", "tiny", "LOW", "1.0.1"),
		"MAL-2024-1":   osvRecord("MAL-2024-1", "npm", "evil", "", ""),
		"GHSA-dj":      osvRecord("GHSA-dj", "PyPI", "Django", "MODERATE", "3.2.4", "CVE-2021-1"),
		"PYSEC-dj":     osvRecord("PYSEC-dj", "PyPI", "django", "", "3.2.4", "CVE-2021-1", "GHSA-dj"),
		"GHSA-w": func() map[string]any {
			r := osvRecord("GHSA-w", "PyPI", "withdrawn", "HIGH", "2.0")
			r["withdrawn"] = "2024-01-01T00:00:00Z"
			return r
		}(),
	})
	snap := depSnapshot(map[string]string{
		"package-lock.json":    lock,
		"api/requirements.txt": "Django==3.2.0\nwithdrawn==1.0\n",
	})
	fs, err := DependencyVulns{OSV: osv}.RunRepo(context.Background(), snap)
	if err != nil {
		t.Fatal(err)
	}
	validateFindings(t, fs)
	type want struct{ key, fixed, advisories string }
	wants := map[string]want{
		"package-lock.json#lodash":    {"vulnerable_dependency_high", "4.17.21", "CVE-2021-23337, GHSA-mod"},
		"package-lock.json#minimist":  {"vulnerable_dependency_medium", "1.2.6", "GHSA-unrated"},
		"package-lock.json#mocha":     {"vulnerable_dev_dependency", "10.1.0", "GHSA-crit"},
		"package-lock.json#left-pad":  {"vulnerable_dependency_no_fix", "", "GHSA-nofix"},
		"package-lock.json#tiny":      {"vulnerable_dependency_low", "1.0.1", "GHSA-low"},
		"package-lock.json#evil":      {"vulnerable_dependency_high", "-", "MAL-2024-1"},
		"api/requirements.txt#django": {"vulnerable_dependency_medium", "3.2.4", "CVE-2021-1"},
	}
	if len(fs) != len(wants) {
		t.Fatalf("got %d findings, want %d: %+v", len(fs), len(wants), fs)
	}
	for _, f := range fs {
		loc := strings.TrimPrefix(f.Evidence.Location, "https://github.com/acme/shop/blob/HEAD/")
		w, ok := wants[loc]
		if !ok {
			t.Errorf("unexpected finding at %s", f.Evidence.Location)
			continue
		}
		if f.FindingKey != w.key || f.Params["fixed_version"] != w.fixed || f.Params["advisories"] != w.advisories {
			t.Errorf("%s: key=%s fixed=%q advisories=%q, want %+v", loc, f.FindingKey, f.Params["fixed_version"], f.Params["advisories"], w)
		}
		if f.Evidence.Kind != evidence.KindDependency || !strings.Contains(f.Evidence.RedactedPayload, "commit 0123456789ab") {
			t.Errorf("%s: evidence %+v", loc, f.Evidence)
		}
	}
}

func TestDependencyVulnsCleanAndEmpty(t *testing.T) {
	osv := fakeOSV(t, nil, nil)
	fs, err := DependencyVulns{OSV: osv}.RunRepo(context.Background(), depSnapshot(map[string]string{
		"package-lock.json": `{"lockfileVersion":3,"packages":{"node_modules/safe":{"version":"1.0.0"}}}`,
		"README.md":         "no deps here",
	}))
	if err != nil || len(fs) != 0 {
		t.Fatalf("clean repo: %v %v", fs, err)
	}
	// No lockfile at all: no OSV query, no finding, no error.
	fs, err = DependencyVulns{OSV: deps.NewOSV("http://127.0.0.1:1", http.DefaultTransport, time.Second, 5)}.RunRepo(context.Background(),
		depSnapshot(map[string]string{"package.json": `{"dependencies":{"lodash":"^4"}}`}))
	if err != nil || len(fs) != 0 {
		t.Fatalf("no lockfile: %v %v", fs, err)
	}
}

func TestDependencyVulnsPartialResults(t *testing.T) {
	osv := fakeOSV(t, map[string][]string{"npm|lodash|4.17.15": {"GHSA-high"}},
		map[string]map[string]any{"GHSA-high": osvRecord("GHSA-high", "npm", "lodash", "HIGH", "4.17.21")})
	snap := depSnapshot(map[string]string{
		"a/package-lock.json": `{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.15"}}}`,
		"b/package-lock.json": "{broken",
	})
	snap.Truncated = true
	fs, err := DependencyVulns{OSV: osv}.RunRepo(context.Background(), snap)
	if len(fs) != 1 || !errors.Is(err, repo.ErrTooLarge) {
		t.Fatalf("partial: %d findings, err %v", len(fs), err)
	}
	snap.Truncated = false
	_, err = DependencyVulns{OSV: osv}.RunRepo(context.Background(), snap)
	if !errors.Is(err, ErrManifestUnreadable) || !strings.Contains(err.Error(), "b/package-lock.json") {
		t.Fatalf("unreadable manifest must be reported: %v", err)
	}
}
