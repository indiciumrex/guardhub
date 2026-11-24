package activescan

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/hksolutions/guardhub/apps/scanner/internal/active"
	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
)

// Every active check in the catalogue (target "active") runs here, and only those.
func TestAllMatchesCatalog(t *testing.T) {
	ids := map[string]bool{}
	for _, c := range All() {
		if !evidence.ActiveChecks[c.ID()] || ids[c.ID()] {
			t.Fatalf("%s is not an active catalogue check, or is listed twice", c.ID())
		}
		ids[c.ID()] = true
	}
	if len(ids) != len(evidence.ActiveChecks) {
		t.Fatalf("All() has %d checks, the catalogue %d", len(ids), len(evidence.ActiveChecks))
	}
}

// labServer is a deliberately imperfect test target: one endpoint reflects a
// parameter into HTML without encoding, one surfaces a database error on an
// odd quote, and one is clean. It is test scaffolding, never shipped.
func labServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body>` +
			`<a href="/reflect?q=hi">r</a><a href="/find?id=1">f</a><a href="/safe?q=1">s</a>` +
			`</body></html>`))
	})
	mux.HandleFunc("/reflect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>you said: " + r.URL.Query().Get("q") + "</body></html>")) // unencoded
	})
	mux.HandleFunc("/safe", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>you said: " + html.EscapeString(r.URL.Query().Get("q")) + "</body></html>")) // encoded
	})
	mux.HandleFunc("/find", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		id := r.URL.Query().Get("id")
		// a lone quote reaches the "database" and errors; the doubled quote does not
		if c := countQuote(id); c%2 == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`<html><body>You have an error in your SQL syntax near '` + id + `'</body></html>`))
			return
		}
		_, _ = w.Write([]byte("<html><body>row " + id + "</body></html>"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func countQuote(s string) int {
	n := 0
	for _, r := range s {
		if r == '\'' {
			n++
		}
	}
	return n
}

func newEnv(t *testing.T, srv *httptest.Server) Env {
	t.Helper()
	origin, _ := url.Parse(srv.URL)
	scope, err := active.NewScope(srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	cl, err := active.NewClient(active.Options{Scope: scope, Kill: &active.StaticKill{}, Log: &active.RequestLog{},
		Timeout: 3 * time.Second, AllowPrivateHosts: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	pts, pages, err := Discover(context.Background(), cl, origin, nil, DiscoveryLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(pts) == 0 || len(pages) == 0 {
		t.Fatalf("discovery found nothing: %d points %d pages", len(pts), len(pages))
	}
	return Env{Client: cl, Origin: origin, Points: pts, Pages: pages}
}

func keys(fs []findingLike) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.CheckID+"/"+f.FindingKey] = true
	}
	return m
}

type findingLike struct{ CheckID, FindingKey string }

func runCheck(t *testing.T, c Check, env Env) []findingLike {
	t.Helper()
	fs, err := c.Run(context.Background(), env)
	if err != nil {
		t.Fatalf("%s: %v", c.ID(), err)
	}
	out := make([]findingLike, len(fs))
	for i, f := range fs {
		out[i] = findingLike{f.CheckID, f.FindingKey}
	}
	return out
}

func TestXSSDetectsReflectionNotEncoded(t *testing.T) {
	env := newEnv(t, labServer(t))
	fs, err := XSS{}.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, f := range fs {
		if f.FindingKey != "reflected_xss" {
			t.Fatalf("unexpected key %s", f.FindingKey)
		}
		paths[f.Params["path"]] = true
	}
	if !paths["/reflect"] {
		t.Fatal("reflected XSS not detected on the unencoded /reflect")
	}
	if paths["/safe"] {
		t.Fatal("XSS reported on /safe, which HTML-encodes its input")
	}
}

func TestSQLiDetectsErrorDifference(t *testing.T) {
	env := newEnv(t, labServer(t))
	if !keys(runCheck(t, SQLi{}, env))["active_sqli/sql_injection"] {
		t.Fatal("error-based SQLi not detected on /find")
	}
}

func TestCleanTargetIsSilent(t *testing.T) {
	// a target that encodes everything and has no quote-sensitive endpoint
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><a href="/safe?q=1">s</a>`))
	})
	mux.HandleFunc("/safe", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("ok: " + html.EscapeString(r.URL.Query().Get("q"))))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	env := newEnv(t, srv)
	for _, c := range []Check{XSS{}, SQLi{}, Redirect{}, CORS{}} {
		if fs := runCheck(t, c, env); len(fs) != 0 {
			t.Errorf("%s fired on a clean target: %+v", c.ID(), fs)
		}
	}
}

func TestDiscoverSkipsLogoutAndStatic(t *testing.T) {
	mux := http.NewServeMux()
	var logoutHit bool
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<a href="/logout">x</a><a href="/app.js">j</a><a href="/p?q=1">p</a>`))
	})
	mux.HandleFunc("/logout", func(http.ResponseWriter, *http.Request) { logoutHit = true })
	mux.HandleFunc("/p", func(w http.ResponseWriter, _ *http.Request) { w.Header().Set("Content-Type", "text/html") })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	origin, _ := url.Parse(srv.URL)
	scope, _ := active.NewScope(srv.URL, nil)
	cl, _ := active.NewClient(active.Options{Scope: scope, Kill: &active.StaticKill{}, Log: &active.RequestLog{}, Timeout: 3 * time.Second, AllowPrivateHosts: []string{"127.0.0.1"}})
	pts, _, err := Discover(context.Background(), cl, origin, nil, DiscoveryLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if logoutHit {
		t.Fatal("discovery followed a logout link")
	}
	for _, p := range pts {
		if p.URL.Path == "/app.js" {
			t.Fatal("discovery treated a static asset as an injection point")
		}
	}
}

func TestSSRFNeedsCollaborator(t *testing.T) {
	env := newEnv(t, labServer(t))
	if fs := runCheck(t, SSRF{}, env); len(fs) != 0 {
		t.Fatalf("SSRF must be silent without a collaborator: %+v", fs)
	}
}
