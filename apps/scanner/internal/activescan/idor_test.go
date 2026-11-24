package activescan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hksolutions/guardhub/apps/scanner/internal/active"
)

// idorLab: two users (cookie sid=a / sid=b). /order?id=N has no ownership
// check (IDOR); /invoice?id=N checks the owner; /post?id=N is public;
// /order/delete?id=N must never be requested.
func idorLab(t *testing.T, deleted *atomic.Int32) *httptest.Server {
	t.Helper()
	owner := map[string]string{"1": "alice@example.test", "2": "bob@example.test"}
	user := func(r *http.Request) string {
		c, err := r.Cookie("sid")
		if err != nil {
			return ""
		}
		return map[string]string{"a": "alice@example.test", "b": "bob@example.test"}[c.Value]
	}
	page := func(w http.ResponseWriter, me, body string) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body><nav>signed in as " + me + "</nav>" + body + "</body></html>"))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		me := user(r)
		if me == "" {
			page(w, "nobody", `<a href="/post?id=1">post</a>`)
			return
		}
		id := map[string]string{"alice@example.test": "1", "bob@example.test": "2"}[me]
		page(w, me, `<a href="/order?id=`+id+`">my order</a><a href="/invoice?id=`+id+`">my invoice</a>`+
			`<a href="/post?id=1">post</a><a href="/order/delete?id=`+id+`">delete order</a>`)
	})
	order := func(check bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			me := user(r)
			o, ok := owner[r.URL.Query().Get("id")]
			if me == "" {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			if !ok || (check && o != me) {
				w.WriteHeader(http.StatusForbidden)
				page(w, me, "forbidden")
				return
			}
			page(w, me, "<h1>Order for "+o+"</h1><p>3 x widget, ship to 1 Example Street, total 42.00 EUR, card ending 4242</p>")
		}
	}
	mux.HandleFunc("/order", order(false))
	mux.HandleFunc("/invoice", order(true))
	mux.HandleFunc("/post", func(w http.ResponseWriter, r *http.Request) {
		page(w, user(r), "<p>Public post by alice@example.test: hello world, welcome to the forum</p>")
	})
	mux.HandleFunc("/order/delete", func(w http.ResponseWriter, _ *http.Request) { deleted.Add(1) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func idorEnv(t *testing.T, srv *httptest.Server, log *active.RequestLog) Env {
	t.Helper()
	origin, _ := url.Parse(srv.URL)
	scope, err := active.NewScope(srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	cl, err := active.NewClient(active.Options{Scope: scope, Kill: &active.StaticKill{}, Log: log,
		Timeout: 3 * time.Second, AllowPrivateHosts: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	return Env{Client: cl, Origin: origin,
		SessionA: &active.Session{Name: "A", Cookie: "sid=a", Marker: "alice@example.test"},
		SessionB: &active.Session{Name: "B", Cookie: "sid=b", Marker: "bob@example.test"}}
}

func TestIDORCrossAccountRead(t *testing.T) {
	var deleted atomic.Int32
	log := &active.RequestLog{}
	env := idorEnv(t, idorLab(t, &deleted), log)
	fs, err := IDOR{}.Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range fs {
		got[f.Params["path"]] = true
	}
	if !got["/order"] {
		t.Fatalf("IDOR on /order (no ownership check) not found: %+v", fs)
	}
	if got["/invoice"] || got["/post"] {
		t.Fatalf("IDOR reported on an owner-checked or public page: %+v", fs)
	}
	if deleted.Load() != 0 {
		t.Fatal("a state-changing link (/order/delete) was requested")
	}
	for _, e := range log.Entries() {
		if strings.Contains(e.Path, "delete") {
			t.Fatalf("request log shows a state-changing request: %+v", e)
		}
	}
}

func TestIDORSilentWithoutSessions(t *testing.T) {
	var deleted atomic.Int32
	env := idorEnv(t, idorLab(t, &deleted), &active.RequestLog{})
	env.SessionB = nil
	if fs, err := (IDOR{}).Run(context.Background(), env); err != nil || len(fs) != 0 {
		t.Fatalf("IDOR must be silent with one session: %v %+v", err, fs)
	}
}

func TestSessionCookieNeverLogged(t *testing.T) {
	var deleted atomic.Int32
	log := &active.RequestLog{}
	env := idorEnv(t, idorLab(t, &deleted), log)
	if _, err := (IDOR{}).Run(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	sawSession := false
	for _, e := range log.Entries() {
		if e.Session != "" {
			sawSession = true
		}
		if strings.Contains(e.Session+e.Path+e.Param, "sid=") {
			t.Fatalf("cookie leaked into the request log: %+v", e)
		}
	}
	if !sawSession {
		t.Fatal("authenticated requests are not marked with the session name")
	}
}

func TestSessionValidate(t *testing.T) {
	bad := []*active.Session{
		nil,
		{Name: "A", Cookie: "sid=a\r\nX-Evil: 1", Marker: "alice@example.test"},
		{Name: "A", Cookie: "sid=a", Marker: "al"},
		{Name: "", Cookie: "sid=a", Marker: "alice@example.test"},
	}
	for i, s := range bad {
		if s.Validate() == nil {
			t.Errorf("session %d accepted", i)
		}
	}
}

func TestUnsafeLink(t *testing.T) {
	for raw, want := range map[string]bool{
		"/order?id=1":           false,
		"/order/delete?id=1":    true,
		"/account?action=close": true,
		"/logout":               true,
		"/api/users/7/revoke":   true,
		"/search?q=shoes":       false,
	} {
		u, _ := url.Parse(raw)
		if got := unsafeLink(u); got != want {
			t.Errorf("unsafeLink(%s) = %v, want %v", raw, got, want)
		}
	}
}

// A DVWA-style GET password-change form must never be requested or probed:
// submitting it with empty passwords would set the account's password.
func TestDiscoverSkipsStateChangingForms(t *testing.T) {
	var changed atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
<form action="/csrf/" method="GET">
  <input type="password" name="password_new"><input type="password" name="password_conf">
  <input type="submit" value="Change" name="Change">
</form>
<form action="/profile" method="GET"><input name="nickname"><input type="submit" value="Update profile"></form>
<form action="/search" method="GET"><input name="q"><input type="submit" value="Search"></form>
</body></html>`))
	})
	mux.HandleFunc("/csrf/", func(http.ResponseWriter, *http.Request) { changed.Add(1) })
	mux.HandleFunc("/profile", func(http.ResponseWriter, *http.Request) { changed.Add(1) })
	mux.HandleFunc("/search", func(w http.ResponseWriter, _ *http.Request) { w.Header().Set("Content-Type", "text/html") })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	origin, _ := url.Parse(srv.URL)
	scope, _ := active.NewScope(srv.URL, nil)
	cl, _ := active.NewClient(active.Options{Scope: scope, Kill: &active.StaticKill{}, Log: &active.RequestLog{},
		Timeout: 3 * time.Second, AllowPrivateHosts: []string{"127.0.0.1"}})
	pts, _, err := Discover(context.Background(), cl, origin, nil, DiscoveryLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if changed.Load() != 0 {
		t.Fatal("a state-changing GET form was requested")
	}
	keys := map[string]bool{}
	for _, p := range pts {
		keys[p.Key()] = true
	}
	if keys["/csrf/?Change"] || keys["/profile?nickname"] || !keys["/search?q"] {
		t.Fatalf("points = %v: change forms must be dropped, the search form kept", keys)
	}
}

// A page that is only reachable logged in (like DVWA's modules) must be tested logged in:
// discovery runs as account A, so every check's probes must carry A's session too (Gate M's
// first CI run found nothing on DVWA because the probes went out anonymously).
func TestChecksProbeAsSessionA(t *testing.T) {
	mux := http.NewServeMux()
	loggedIn := func(r *http.Request) bool { c, err := r.Cookie("sid"); return err == nil && c.Value == "a" }
	mux.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>please log in</body></html>`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !loggedIn(r) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>alice@example.test <a href="/q?name=x">search</a></body></html>`))
	})
	mux.HandleFunc("/q", func(w http.ResponseWriter, r *http.Request) {
		if !loggedIn(r) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>Hello " + r.URL.Query().Get("name") + "</body></html>")) //nolint:gosec // deliberately vulnerable test server
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	for _, tc := range []struct {
		name string
		sess *active.Session
		want bool
	}{
		{"with session A", &active.Session{Name: "A", Cookie: "sid=a", Marker: "alice@example.test"}, true},
		{"anonymous", nil, false},
	} {
		env := idorEnv(t, srv, &active.RequestLog{})
		scope, _ := active.NewScope(srv.URL, nil)
		fs, outs := Run(context.Background(), env.Client, scope, []string{"active_xss"}, tc.sess, nil, nil)
		for _, o := range outs {
			if o.Err != nil {
				t.Fatalf("%s: %s: %v", tc.name, o.CheckID, o.Err)
			}
		}
		if got := len(fs) > 0; got != tc.want {
			t.Fatalf("%s: found=%v (%d findings), want %v", tc.name, got, len(fs), tc.want)
		}
	}
}

// A boolean-blind injection whose only signal is the status code (200 "exists" for the true
// condition and the original request, 404 "missing" for the false one, nearly the same words)
// is reported (DVWA sqli_blind); a page that answers every input the same is not.
func TestSQLiBooleanByStatus(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href="/user?id=1">user</a><a href="/same?id=1">same</a></body></html>`))
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		id := r.URL.Query().Get("id")
		if id == "1" || strings.HasSuffix(id, "'7'='7") || strings.HasSuffix(id, "7=7") {
			_, _ = w.Write([]byte("<html><body>User ID exists in the database.</body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>User ID is MISSING from the database.</body></html>"))
	})
	mux.HandleFunc("/same", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>Nothing to see.</body></html>"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	env := idorEnv(t, srv, &active.RequestLog{})
	scope, _ := active.NewScope(srv.URL, nil)
	fs, _ := Run(context.Background(), env.Client, scope, []string{"active_sqli"}, nil, nil, nil)
	if len(fs) != 1 || fs[0].Params["path"] != "/user" || fs[0].Params["technique"] != "boolean" {
		t.Fatalf("findings = %+v, want exactly one boolean finding on /user", fs)
	}
}

// Parameters of a link count as injection points as soon as the link is seen, even when the
// page cap stops discovery from fetching it (DVWA's open-redirect links).
func TestLinkPointsBeyondPageCap(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href='/go?redirect=info.php'>q</a><a href="/logout?next=/">out</a></body></html>`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	env := idorEnv(t, srv, &active.RequestLog{})
	pts, _, err := Discover(context.Background(), env.Client, env.Origin, nil, DiscoveryLimits{MaxPages: 1})
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	for _, p := range pts {
		keys[p.Key()] = true
	}
	if !keys["/go?redirect"] || keys["/logout?next"] {
		t.Fatalf("points = %v: the link's parameter must be kept, the logout link's never", keys)
	}
}
