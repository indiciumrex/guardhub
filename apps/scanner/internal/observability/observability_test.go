package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"
)

const testDSNKey = "0123456789abcdef0123456789abcdef"

func lookup(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestFromLookupDefaultsAndOff(t *testing.T) {
	cfg := FromLookup(lookup(nil))
	if cfg.Enabled() || cfg.Environment != "production" || cfg.Release != "" {
		t.Fatalf("unexpected default config: %+v", cfg)
	}
	ok, err := Init(cfg)
	if ok || err != nil {
		t.Fatalf("Init without DSN must be a no-op, got %v %v", ok, err)
	}
	cfg = FromLookup(lookup(map[string]string{
		"SENTRY_DSN": " https://k@example.invalid/1 ", "SENTRY_ENVIRONMENT": "staging", "GUARDHUB_VERSION": "1.2.3",
	}))
	if !cfg.Enabled() || cfg.DSN != "https://k@example.invalid/1" || cfg.Environment != "staging" || cfg.Release != "1.2.3" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	// The per-service DSN wins over the shared fallback.
	cfg = FromLookup(lookup(map[string]string{
		"SENTRY_DSN": "https://k@example.invalid/1", "SENTRY_DSN_SCANNER": "https://s@o1.ingest.de.sentry.io/2",
	}))
	if cfg.DSN != "https://s@o1.ingest.de.sentry.io/2" {
		t.Fatalf("SENTRY_DSN_SCANNER must win, got %q", cfg.DSN)
	}
}

func TestOptionsAreErrorsOnlyAndPrivate(t *testing.T) {
	o := Config{DSN: "https://k@example.invalid/1", Environment: "production"}.Options(nil)
	if o.SendDefaultPII || o.EnableTracing || o.TracesSampleRate != 0 || o.Tags["service"] != "scanner" { //nolint:staticcheck // asserts the deprecated PII flag stays off (§9)
		t.Fatalf("options not errors-only/private: %+v", o)
	}
	if o.BeforeSendTransaction(&sentry.Event{}, nil) != nil {
		t.Fatal("transactions must be dropped")
	}
}

func TestScrubRemovesSensitiveData(t *testing.T) {
	e := &sentry.Event{
		Message: "verify failed for https://shop.example/x?token=abc from 203.0.113.9 (alice@example.com)",
		User:    sentry.User{ID: "u1", Email: "alice@example.com", IPAddress: "203.0.113.9"},
		Request: &sentry.Request{
			URL:         "https://user:pw@guardhub.example/api/v1/scan?locale=en",
			Method:      "POST",
			Data:        `{"password":"hunter2"}`,
			QueryString: "locale=en&token=abc",
			Cookies:     "gh_session=eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl",
			Headers: map[string]string{
				"Authorization": "Bearer abcdefghijklmnop", "Cookie": "gh_session=x", "X-Scan-Token": "scan-tok",
				"X-GuardHub-CSRF": "1", "X-Forwarded-For": "203.0.113.9", "User-Agent": "GuardHub-Scanner/1.0",
			},
			Env: map[string]string{"REMOTE_ADDR": "203.0.113.9"},
		},
		Exception: []sentry.Exception{{
			Type:  "*errors.errorString",
			Value: "dial redis://:s3cretpass@redis:6379/0: token ghv_abcdefghijkl",
			Stacktrace: &sentry.Stacktrace{Frames: []sentry.Frame{{
				Function: "f", Vars: map[string]interface{}{"password": "hunter2"},
			}}},
		}},
		Contexts: map[string]sentry.Context{"log": {"job_id": "j1", "token": "ghv_secretvalue1", "nested": map[string]interface{}{"Authorization": "Basic Zm9vOmJhcg=="}}},
		Tags:     map[string]string{"service": "scanner", "session": "abc"},
		Breadcrumbs: []*sentry.Breadcrumb{{
			Message: "GET https://example.com/x?secret=1",
			Data:    map[string]interface{}{"url": "https://example.com/x?secret=1", "status_code": 200},
		}},
	}
	out := Scrub(e)
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	dumped := string(raw)
	for _, leaked := range []string{
		"alice@example.com", "203.0.113.9", "hunter2", "s3cretpass", "ghv_abcdefghijkl", "ghv_secretvalue1",
		"abcdefghijklmnop", "scan-tok", "gh_session", "token=abc", "secret=1", "Zm9vOmJhcg==", "eyJhbGciOi",
		"user:pw", "locale=en",
	} {
		if strings.Contains(dumped, leaked) {
			t.Errorf("leaked %q in %s", leaked, dumped)
		}
	}
	if out.Request.URL != "https://guardhub.example/api/v1/scan" || out.Request.Method != "POST" {
		t.Errorf("request not reduced to method+path: %+v", out.Request)
	}
	if len(out.Request.Headers) != 1 || out.Request.Headers["User-Agent"] == "" {
		t.Errorf("only safe headers may stay: %+v", out.Request.Headers)
	}
	if out.Exception[0].Stacktrace.Frames[0].Vars != nil {
		t.Error("frame variables must be removed")
	}
	if out.Contexts["log"]["job_id"] != "j1" || out.Tags["service"] != "scanner" {
		t.Error("harmless data must stay")
	}
	if Scrub(nil) != nil {
		t.Error("Scrub(nil) must be nil")
	}
}

func TestScrubTextKeepsHarmlessText(t *testing.T) {
	const s = "check tls_cert failed: timeout after 10s (v0.50.0)"
	if got := ScrubText(s); got != s {
		t.Fatalf("got %q", got)
	}
}

// memTransport records events after BeforeSend, standing in for the network.
type memTransport struct {
	mu     sync.Mutex
	events []*sentry.Event
}

func (m *memTransport) Flush(time.Duration) bool              { return true }
func (m *memTransport) FlushWithContext(context.Context) bool { return true }
func (m *memTransport) Configure(sentry.ClientOptions)        {}
func (m *memTransport) Close()                                {}
func (m *memTransport) SendEvent(e *sentry.Event) {
	m.mu.Lock()
	m.events = append(m.events, e)
	m.mu.Unlock()
}
func (m *memTransport) all() []*sentry.Event { m.mu.Lock(); defer m.mu.Unlock(); return m.events }

func TestHandlerReportsOnlyErrorsAndScrubs(t *testing.T) {
	mem := &memTransport{}
	opts := Config{DSN: "https://" + testDSNKey + "@example.invalid/1", Environment: "test"}.Options(nil)
	opts.Transport = mem
	client, err := sentry.NewClient(opts)
	if err != nil {
		t.Fatal(err)
	}
	hub := sentry.NewHub(client, sentry.NewScope())
	var buf bytes.Buffer
	logger := slog.New(NewHandler(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}), hub)).
		With("service", "scanner")

	logger.Info("not sent, not printed")
	logger.Warn("printed only")
	logger.Error("XACK failed", "err", errors.New("dial redis://:pw@redis:6379"), "job_id", "j1", "token", "ghv_abcdefghijkl")
	client.Flush(time.Second)

	events := mem.all()
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Message != "XACK failed" || ev.Tags["service"] != "scanner" || ev.Environment != "test" {
		t.Fatalf("unexpected event: %+v", ev)
	}
	if len(ev.Exception) != 1 || strings.Contains(ev.Exception[0].Value, ":pw@") {
		t.Fatalf("exception missing or not scrubbed: %+v", ev.Exception)
	}
	if ev.Contexts["log"]["token"] != Filtered || ev.Contexts["log"]["job_id"] != "j1" {
		t.Fatalf("log context not scrubbed: %+v", ev.Contexts["log"])
	}
	if !strings.Contains(buf.String(), "printed only") || strings.Contains(buf.String(), "not printed") ||
		!strings.Contains(buf.String(), "XACK failed") {
		t.Fatalf("inner handler output wrong: %s", buf.String())
	}
}

func TestSendTestEvent(t *testing.T) {
	var gotAuth, gotPath string
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("X-Sentry-Auth")
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(status)
	}))
	defer srv.Close()
	dsn := strings.Replace(srv.URL, "http://", "http://"+testDSNKey+"@", 1) + "/42"

	var out bytes.Buffer
	if code := SendTestEvent(context.Background(), Config{}, &out, nil); code != 2 {
		t.Fatalf("no DSN: want exit 2, got %d", code)
	}

	out.Reset()
	if code := SendTestEvent(context.Background(), Config{DSN: dsn, Environment: "test"}, &out, nil); code != 0 {
		t.Fatalf("want exit 0, got %d: %s", code, out.String())
	}
	if gotPath != "/api/42/envelope/" || !strings.Contains(gotAuth, testDSNKey) {
		t.Fatalf("unexpected request %q %q", gotPath, gotAuth)
	}
	if !strings.Contains(out.String(), "Sent test event") {
		t.Fatalf("unexpected output %q", out.String())
	}

	status = http.StatusBadRequest
	out.Reset()
	if code := SendTestEvent(context.Background(), Config{DSN: dsn}, &out, nil); code != 1 {
		t.Fatalf("rejected: want exit 1, got %d: %s", code, out.String())
	}

	srv.Close()
	out.Reset()
	if code := SendTestEvent(context.Background(), Config{DSN: dsn}, &out, nil); code != 1 {
		t.Fatalf("unreachable: want exit 1, got %d: %s", code, out.String())
	}
}
