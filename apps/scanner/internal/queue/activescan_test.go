package queue

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hksolutions/guardhub/apps/scanner/internal/active"
)

// activeTarget: a lab app that proves ownership with the well-known file
// (when token != "") and reflects ?q= unencoded. It records every request.
type activeTarget struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []string
}

func newActiveTarget(t *testing.T, token string) *activeTarget {
	t.Helper()
	at := &activeTarget{}
	at.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		at.mu.Lock()
		at.reqs = append(at.reqs, r.URL.RequestURI())
		at.mu.Unlock()
		switch r.URL.Path {
		case "/.well-known/guardhub-verify.txt":
			if token == "" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(token + "\n"))
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body><a href="/reflect?q=hi">r</a></body></html>`))
		case "/reflect":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body>you said: " + r.URL.Query().Get("q") + "</body></html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(at.srv.Close)
	return at
}

// probed returns the requests other than the ownership proof's.
func (at *activeTarget) probed() []string {
	at.mu.Lock()
	defer at.mu.Unlock()
	var out []string
	for _, r := range at.reqs {
		if r != "/.well-known/guardhub-verify.txt" {
			out = append(out, r)
		}
	}
	return out
}

func activeJob(target string, checkIDs ...string) map[string]any {
	return map[string]any{"v": 1, "kind": "active_scan", "job_id": "ajob-1", "scan_id": "ascan-1", "target": target,
		"checks": checkIDs, "consent_id": "consent-1", "token": "ghv_active123", "session_key": ActiveSessionPrefix + "ajob-1"}
}

func activeEnv(t *testing.T, enabled bool) *env {
	t.Helper()
	e := newEnv(t, []string{"127.0.0.1"}, nil)
	lim := active.DefaultLimits()
	lim.RPS = 200
	e.svc.Active = ActiveConfig{Enabled: enabled, Limits: lim, AllowPrivateHosts: []string{"127.0.0.1"}}
	return e
}

func lastEventOf(t *testing.T, e *env, typ string) map[string]any {
	t.Helper()
	var last map[string]any
	for _, ev := range e.events(t) {
		if ev["type"] == typ {
			last = ev
		}
	}
	if last == nil {
		t.Fatalf("no %s event in %v", typ, e.events(t))
	}
	return last
}

func TestActiveScanRefusedWhenDisabled(t *testing.T) {
	at := newActiveTarget(t, "ghv_active123")
	e := activeEnv(t, false)
	_ = e.mr.Set(ActiveSessionPrefix+"ajob-1", `{"a":{"name":"A","cookie":"sid=a","marker":"alice@example.test"}}`)
	e.enqueue(t, activeJob(at.srv.URL, "active_xss"))
	e.processOne(t)
	if got := lastEventOf(t, e, EventScanFailed)["error"]; got != ErrCodeActiveDisabled {
		t.Fatalf("error = %v, want %s", got, ErrCodeActiveDisabled)
	}
	if n := len(at.reqs); n != 0 {
		t.Fatalf("a disabled scanner sent %d requests to the target", n)
	}
	if e.mr.Exists(ActiveSessionPrefix + "ajob-1") {
		t.Fatal("the session record must be deleted even when the scan is refused")
	}
	if e.pendingCount(t) != 0 {
		t.Fatal("must be acked")
	}
}

func TestActiveScanRefusedWhenKilled(t *testing.T) {
	at := newActiveTarget(t, "ghv_active123")
	e := activeEnv(t, true)
	_ = e.mr.Set(active.GlobalKillKey, "1")
	e.enqueue(t, activeJob(at.srv.URL, "active_xss"))
	e.processOne(t)
	if got := lastEventOf(t, e, EventScanFailed)["error"]; got != ErrCodeActiveKilled {
		t.Fatalf("error = %v, want %s", got, ErrCodeActiveKilled)
	}
	if n := len(at.reqs); n != 0 {
		t.Fatalf("a killed scan sent %d requests", n)
	}
}

func TestActiveScanNeedsFreshOwnershipProof(t *testing.T) {
	at := newActiveTarget(t, "") // the proof is gone
	e := activeEnv(t, true)
	e.enqueue(t, activeJob(at.srv.URL, "active_xss"))
	e.processOne(t)
	if got := lastEventOf(t, e, EventScanFailed)["error"]; got != ErrCodeOwnershipUnproven {
		t.Fatalf("error = %v, want %s", got, ErrCodeOwnershipUnproven)
	}
	for _, r := range at.probed() {
		if r != "/" { // the meta-tag proof reads the home page; nothing else may be sent
			t.Fatalf("an unproven target received %q", r)
		}
	}
}

func TestActiveScanEndToEnd(t *testing.T) {
	at := newActiveTarget(t, "ghv_active123")
	e := activeEnv(t, true)
	e.enqueue(t, activeJob(at.srv.URL, "active_xss", "active_idor"))
	e.processOne(t)
	evs := e.events(t)
	logIdx, doneIdx := -1, -1
	for i, ev := range evs {
		switch ev["type"] {
		case EventActiveRequestLog:
			logIdx = i
		case EventScanCompleted:
			doneIdx = i
		}
	}
	if logIdx < 0 || doneIdx < 0 || logIdx > doneIdx {
		t.Fatalf("want active.request_log before scan.completed: %v", evs)
	}
	reqLog := evs[logIdx]
	if reqLog["consent_id"] != "consent-1" || len(reqLog["entries"].([]any)) == 0 {
		t.Fatalf("request log event incomplete: %v", reqLog)
	}
	done := evs[doneIdx]
	fs := done["findings"].([]any)
	found := false
	for _, f := range fs {
		if f.(map[string]any)["check_id"] == "active_xss" {
			found = true
		}
	}
	if !found {
		t.Fatalf("reflected XSS not reported: %v", fs)
	}
	for _, r := range done["check_results"].([]any) {
		if r.(map[string]any)["status"] != "done" {
			t.Fatalf("check not done: %v", r)
		}
	}
	for _, r := range at.probed() {
		if strings.Contains(r, "logout") {
			t.Fatalf("unexpected request %q", r)
		}
	}
}

func TestParseActiveJobValidation(t *testing.T) {
	base := func() map[string]any { return activeJob("https://example.com", "active_xss") }
	cases := map[string]func(m map[string]any){
		"passive check":   func(m map[string]any) { m["checks"] = []string{"security_headers"} },
		"no checks":       func(m map[string]any) { m["checks"] = []string{} },
		"no consent":      func(m map[string]any) { delete(m, "consent_id") },
		"no token":        func(m map[string]any) { delete(m, "token") },
		"bad session key": func(m map[string]any) { m["session_key"] = "gh:other:ajob-1" },
		"bad exclude":     func(m map[string]any) { m["exclude"] = []string{"admin"} },
	}
	for name, mutate := range cases {
		m := base()
		mutate(m)
		if _, err := ParseJob(mustJSON(t, m)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseJob(mustJSON(t, base())); err != nil {
		t.Fatalf("valid job refused: %v", err)
	}
	if d := (Job{DeadlineSeconds: 99999}).ActiveDeadline(); d != MaxActiveDeadline {
		t.Fatalf("deadline not clamped: %v", d)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
