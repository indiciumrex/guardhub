package queue

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hksolutions/guardhub/apps/scanner/internal/checks"
	"github.com/hksolutions/guardhub/apps/scanner/internal/deps"
	"github.com/hksolutions/guardhub/apps/scanner/internal/labfixture"
	"github.com/hksolutions/guardhub/apps/scanner/internal/repo"
)

const repoSHA = "aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd"

func gzTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: "acme-app-aaaaaaa/" + name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// repoEnv: a queue env plus fake GitHub (one repo, acme/app) and fake OSV.
func repoEnv(t *testing.T, files map[string]string) (*env, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	e := newEnv(t, nil, nil)
	var revoked, tarballs atomic.Int32
	data := gzTar(t, files)
	gh := http.NewServeMux()
	ok := func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer one-time-token" }
	gh.HandleFunc("GET /repos/acme/app", func(w http.ResponseWriter, r *http.Request) {
		if !ok(r) {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"default_branch":"main"}`))
	})
	gh.HandleFunc("GET /repos/acme/app/commits/main", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(repoSHA)) })
	gh.HandleFunc("GET /repos/acme/app/tarball/"+repoSHA, func(w http.ResponseWriter, _ *http.Request) {
		tarballs.Add(1)
		_, _ = w.Write(data)
	})
	gh.HandleFunc("GET /repos/acme/gone", func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	gh.HandleFunc("DELETE /installation/token", func(w http.ResponseWriter, r *http.Request) {
		if ok(r) {
			revoked.Add(1)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	ghSrv := httptest.NewServer(gh)
	t.Cleanup(ghSrv.Close)
	osv := http.NewServeMux()
	osv.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Queries []struct {
				Package struct{ Name string } `json:"package"`
			} `json:"queries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		res := make([]map[string]any, len(body.Queries))
		for i, q := range body.Queries {
			res[i] = map[string]any{}
			if q.Package.Name == "lodash" {
				res[i] = map[string]any{"vulns": []map[string]string{{"id": "GHSA-l"}}}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": res})
	})
	osv.HandleFunc("GET /v1/vulns/GHSA-l", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"GHSA-l","database_specific":{"severity":"HIGH"},"affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`))
	})
	osvSrv := httptest.NewServer(osv)
	t.Cleanup(osvSrv.Close)
	e.svc.RepoRegistry = checks.NewRepoRegistry(
		checks.DependencyVulns{OSV: deps.NewOSV(osvSrv.URL, http.DefaultTransport, 5*time.Second, 50)},
		checks.RepoSecrets{},
	)
	e.svc.Repo = RepoScanConfig{GitHubAPI: ghSrv.URL, Transport: http.DefaultTransport, Timeout: 5 * time.Second, Limits: repo.DefaultLimits()}
	return e, &revoked, &tarballs
}

func repoJob(jobID, repoName string) map[string]any {
	return map[string]any{"v": 1, "kind": "repo_scan", "job_id": jobID, "scan_id": "scan-" + jobID, "repo": repoName,
		"token_key": RepoTokenPrefix + jobID, "checks": []string{"dependency_vulns", "repo_secrets"}, "deadline_seconds": 60}
}

func TestRepoScanEndToEnd(t *testing.T) {
	e, revoked, _ := repoEnv(t, map[string]string{
		"package-lock.json": `{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.15"}}}`,
		"deploy.sh":         "export NPM_TOKEN=" + labfixture.MustSecret("npm_token", "q1") + "\n",
	})
	ctx := context.Background()
	if err := e.rdb.Set(ctx, RepoTokenPrefix+"r1", "one-time-token", time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	e.enqueue(t, repoJob("r1", "acme/app"))
	e.processOne(t)

	evs := e.events(t)
	if len(evs) != 2 || evs[0]["type"] != EventScanStarted || evs[1]["type"] != EventScanCompleted {
		t.Fatalf("events = %v", evs)
	}
	findings, _ := evs[1]["findings"].([]any)
	keys := map[string]bool{}
	for _, f := range findings {
		m := f.(map[string]any)
		keys[m["check_id"].(string)+"."+m["finding_key"].(string)] = true
	}
	if !keys["dependency_vulns.vulnerable_dependency_high"] || !keys["repo_secrets.hardcoded_secret"] || len(findings) != 2 {
		t.Fatalf("findings = %v", findings)
	}
	for _, r := range evs[1]["check_results"].([]any) {
		if r.(map[string]any)["status"] != "done" {
			t.Fatalf("check results = %v", evs[1]["check_results"])
		}
	}
	if n, _ := e.rdb.Exists(ctx, RepoTokenPrefix+"r1").Result(); n != 0 {
		t.Fatal("the token key must be consumed (GETDEL)")
	}
	if revoked.Load() != 1 {
		t.Fatalf("token revoked %d times, want 1", revoked.Load())
	}
	if e.pendingCount(t) != 0 {
		t.Fatal("job must be acked")
	}
}

func TestRepoScanTokenMissingFailsWithoutCallingGitHub(t *testing.T) {
	e, revoked, tarballs := repoEnv(t, map[string]string{"a.txt": "x"})
	e.enqueue(t, repoJob("r2", "acme/app")) // no token key set (expired, or a redelivery)
	e.processOne(t)
	evs := e.events(t)
	if len(evs) != 1 || evs[0]["type"] != EventScanFailed || evs[0]["error"] != ErrCodeInternal {
		t.Fatalf("events = %v", evs)
	}
	if tarballs.Load() != 0 || revoked.Load() != 0 {
		t.Fatal("no GitHub call without a token")
	}
}

func TestRepoScanAccessLost(t *testing.T) {
	e, revoked, _ := repoEnv(t, nil)
	_ = e.rdb.Set(context.Background(), RepoTokenPrefix+"r3", "one-time-token", time.Minute).Err()
	e.enqueue(t, repoJob("r3", "acme/gone"))
	e.processOne(t)
	evs := e.events(t)
	last := evs[len(evs)-1]
	if last["type"] != EventScanFailed || last["error"] != ErrCodeRepoAccessLost {
		t.Fatalf("events = %v", evs)
	}
	if revoked.Load() != 1 {
		t.Fatal("the token is revoked on failure too")
	}
}

func TestParseRepoJob(t *testing.T) {
	good, _ := json.Marshal(repoJob("r4", "acme/app"))
	if j, err := ParseJob(string(good)); err != nil || j.Repo != "acme/app" {
		t.Fatalf("valid repo job: %v", err)
	}
	for name, mutate := range map[string]func(m map[string]any){
		"bad repo":      func(m map[string]any) { m["repo"] = "../x" },
		"foreign token": func(m map[string]any) { m["token_key"] = "gh:repo-token:other" },
		"site check":    func(m map[string]any) { m["checks"] = []string{"exposed_env"} },
		"missing scan":  func(m map[string]any) { delete(m, "scan_id") },
		"token in job":  func(m map[string]any) { m["token_key"] = "ghs_raw" },
	} {
		m := repoJob("r4", "acme/app")
		mutate(m)
		b, _ := json.Marshal(m)
		if _, err := ParseJob(string(b)); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
}
