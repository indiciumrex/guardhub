package queue

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
)

func selfScanTarget(t *testing.T, token string, hits *atomic.Int32) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/.well-known/guardhub-verify.txt":
			if token == "" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(token + "\n"))
		case "/.env":
			_, _ = w.Write([]byte("DB_PASSWORD=supersecretvalue1234\nAPI_KEY=abcdefghijklmnop\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestSelfScanVerifiesThenRunsAllChecks(t *testing.T) {
	var hits atomic.Int32
	target := selfScanTarget(t, "ghv_self", &hits)
	host, _ := url.Parse(target)
	e := newEnv(t, []string{host.Hostname()}, nil)

	report, err := e.svc.SelfScan(context.Background(), target, "ghv_self")
	if err != nil {
		t.Fatal(err)
	}
	if report.VerifiedBy != MethodWellKnown {
		t.Fatalf("verified_by = %q", report.VerifiedBy)
	}
	if len(report.CheckResults) != len(e.svc.Registry.IDs()) {
		t.Fatalf("expected a result per registered check, got %d", len(report.CheckResults))
	}
	var sawEnv, sawPanic bool
	for _, f := range report.Findings {
		if f.CheckID == evidence.CheckExposedEnv && f.FindingKey == "env_file_exposed" {
			sawEnv = true
		}
	}
	for _, r := range report.CheckResults {
		if r.Status == "failed" && r.Error != nil && *r.Error == ErrCodeInternal {
			sawPanic = true // panicCheck is contained, not fatal
		}
	}
	if !sawEnv || !sawPanic {
		t.Fatalf("sawEnv=%v sawPanic=%v report=%+v", sawEnv, sawPanic, report)
	}
}

func TestSelfScanWithoutProofScansNothing(t *testing.T) {
	var hits atomic.Int32
	target := selfScanTarget(t, "", &hits)
	host, _ := url.Parse(target)
	e := newEnv(t, []string{host.Hostname()}, fakeResolver{})

	_, err := e.svc.SelfScan(context.Background(), target, "ghv_self")
	if !errors.Is(err, ErrNotVerified) {
		t.Fatalf("want ErrNotVerified, got %v", err)
	}
	// only the verification probes (well-known file + home page) may have been sent
	if n := hits.Load(); n > 2 {
		t.Fatalf("checks ran without ownership proof: %d requests", n)
	}
}
