package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/hksolutions/guardhub/apps/scanner/internal/active"
)

// The proof against a local site: every scope probe refused before the
// network, the excluded path never requested, 1 request/s, and the kill key
// (set after 3 sent requests) stops the scan within 2 s.
func TestActiveProofScopeKillAndRate(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.RequestURI())
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<a href="/admin/x?id=1">a</a>`)
		for i := range 6 {
			fmt.Fprintf(w, `<a href="/p%d?q=v">p</a>`, i)
		}
		fmt.Fprint(w, `<p>`+strings.ReplaceAll(r.URL.Query().Get("q"), "<", "&lt;")+`</p>`)
	}))
	defer srv.Close()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	rep, code := activeProof(context.Background(), rdb, proofOptions{Origin: srv.URL, Check: "active_xss",
		ScanID: "s1", Exclude: []string{"/admin"}, KillAfter: 3}, []string{"127.0.0.1"}, 3*time.Second, logger)
	if code != 0 {
		t.Fatalf("code %d, failed %v, kill %+v, err %q", code, rep.Failed, rep.Kill, rep.CheckError)
	}
	for _, p := range rep.ScopeProbes {
		if p.Outcome != active.OutcomeScope {
			t.Errorf("scope probe %s: %s", p.URL, p.Outcome)
		}
	}
	if len(rep.ScopeProbes) < 13 {
		t.Fatalf("too few scope probes: %d", len(rep.ScopeProbes))
	}
	mu.Lock()
	defer mu.Unlock()
	for _, p := range paths {
		if strings.HasPrefix(strings.ToLower(p), "/admin") || strings.Contains(p, "gh-scope-probe") {
			t.Fatalf("out-of-scope path reached the server: %s", p)
		}
	}
	if !rep.Kill.SetByProof || rep.Kill.SeenAt == nil || rep.Kill.StopLatencyMS > 2000 || rep.Sent > 6 {
		t.Fatalf("kill: %+v sent %d", rep.Kill, rep.Sent)
	}
	if rep.MinGapMS >= 0 && rep.MinGapMS < 900 {
		t.Fatalf("rate: min gap %d ms", rep.MinGapMS)
	}
	if len(paths) != rep.Sent {
		t.Fatalf("server saw %d requests, log says %d sent", len(paths), rep.Sent)
	}
}

// A kill key set before the start: nothing is sent.
func TestActiveProofKilledBeforeStart(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer srv.Close()
	mr := miniredis.RunT(t)
	if err := mr.Set(active.GlobalKillKey, "1"); err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	_, code := activeProof(context.Background(), rdb, proofOptions{Origin: srv.URL, Check: "active_xss", ScanID: "s2"},
		[]string{"127.0.0.1"}, time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if code != 5 || hits != 0 {
		t.Fatalf("code %d hits %d", code, hits)
	}
}

func TestScopeProbeURLsCoverExcludedForms(t *testing.T) {
	origin, err := url.Parse("https://guardhub.dev")
	if err != nil {
		t.Fatal(err)
	}
	list := scopeProbeURLs(origin, []string{"/admin/"})
	joined := strings.Join(list, " ")
	for _, want := range []string{"http://guardhub.dev/", "https://guardhub.dev:8443/", "https://gh-scope-probe.guardhub.dev/",
		"/gh-scope-probe/%2e%2e/admin", "/admin;gh=1", "/%5Cadmin", "/ADMIN", "https://gh@guardhub.dev/"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %s", want)
		}
	}
}
