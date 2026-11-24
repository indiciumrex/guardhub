package active

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func mustScope(t *testing.T, origin string, exclude ...string) Scope {
	t.Helper()
	s, err := NewScope(origin, exclude)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestScopeCheck(t *testing.T) {
	s := mustScope(t, "https://Shop.example.com", "/admin", "/api/internal/")
	ok := []string{"https://shop.example.com/", "https://SHOP.example.com/search?q=1", "https://shop.example.com:443/a", "https://shop.example.com/administrator",
		"https://shop.example.com/x/../administrator", "https://shop.example.com/a;b/c"}
	bad := []string{
		"http://shop.example.com/", "https://shop.example.com:8443/", "https://evil.example.com/",
		"https://sub.shop.example.com/", "https://shop.example.com.evil.test/", "https://user@shop.example.com/",
		"https://shop.example.com/admin", "https://shop.example.com/Admin/users", "https://shop.example.com//admin/x",
		"https://shop.example.com/api/internal/x", "https://shop.example.com/admin%2Fusers",
		// forms a server resolves to an excluded path
		"https://shop.example.com/x/../admin", "https://shop.example.com/x/%2e%2e/admin/users",
		"https://shop.example.com/x/%2E%2E/%2E%2E/admin", "https://shop.example.com/./admin",
		"https://shop.example.com/admin;jsessionid=1", "https://shop.example.com/admin;x/users",
		"https://shop.example.com/%5Cadmin", "https://shop.example.com/x%5C..%5Cadmin",
		"https://shop.example.com/api/./internal/x",
	}
	for _, raw := range ok {
		if err := s.Check(mustURL(t, raw)); err != nil {
			t.Errorf("%s refused", raw)
		}
	}
	for _, raw := range bad {
		if err := s.Check(mustURL(t, raw)); !errors.Is(err, ErrOutOfScope) {
			t.Errorf("%s allowed", raw)
		}
	}
	for _, o := range []string{"https://x.example/path", "ftp://x.example", "https://u:p@x.example", "https://x.example/?q=1"} {
		if _, err := NewScope(o, nil); err == nil {
			t.Errorf("scope %q accepted", o)
		}
	}
}

func newTestClient(t *testing.T, srv *httptest.Server, kill KillSwitch, lim Limits, exclude ...string) (*Client, *RequestLog) {
	t.Helper()
	log := &RequestLog{}
	if lim == (Limits{}) {
		lim = DefaultLimits()
		lim.RPS = 1000
	}
	c, err := NewClient(Options{Scope: mustScope(t, srv.URL, exclude...), Kill: kill, Limits: lim, Log: log,
		Timeout: 3 * time.Second, AllowPrivateHosts: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	return c, log
}

func TestClientSendsOnlyInScope(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/go-out":
			http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
		case "/go-in":
			http.Redirect(w, r, "/landing", http.StatusFound)
		case "/go-excluded":
			http.Redirect(w, r, "/admin/x", http.StatusFound)
		default:
			_, _ = w.Write([]byte("q=" + r.URL.Query().Get("q") + " origin=" + r.Header.Get("Origin")))
		}
	}))
	defer srv.Close()
	c, log := newTestClient(t, srv, &StaticKill{}, Limits{}, "/admin")
	ctx := context.Background()
	base := mustURL(t, srv.URL+"/search?page=2")

	p, _ := PayloadByID("xss.marker.tag")
	resp, err := c.Send(ctx, Probe("active_xss", base, "q", p))
	if err != nil || string(resp.Body) != "q="+p.Value+" origin=" {
		t.Fatalf("probe: %v %q", err, resp.Body)
	}
	if resp.URL.Query().Get("page") != "2" {
		t.Fatalf("other query params must stay: %s", resp.URL)
	}
	o, _ := PayloadByID("cors.canary.origin")
	resp, _ = c.Send(ctx, Probe("active_cors", base, "", o))
	if string(resp.Body) != "q= origin=https://"+CanaryHost {
		t.Fatalf("origin header: %q", resp.Body)
	}
	// cross-origin redirect: returned, never followed
	resp, err = c.Send(ctx, Baseline("active_redirect", mustURL(t, srv.URL+"/go-out")))
	if err != nil || resp.Location != "https://elsewhere.example/" || resp.Status != 302 {
		t.Fatalf("cross-origin redirect: %v %+v", err, resp)
	}
	// same-origin redirect: followed
	resp, _ = c.Send(ctx, Baseline("active_redirect", mustURL(t, srv.URL+"/go-in")))
	if resp.URL.Path != "/landing" || resp.Status != 200 {
		t.Fatalf("same-origin redirect not followed: %+v", resp)
	}
	// redirect into an excluded path: not followed
	before := hits.Load()
	resp, _ = c.Send(ctx, Baseline("active_redirect", mustURL(t, srv.URL+"/go-excluded")))
	if resp.Location != "/admin/x" || hits.Load() != before+1 {
		t.Fatalf("excluded redirect target was requested")
	}
	// out of scope requests never reach the network
	before = hits.Load()
	for _, raw := range []string{"https://elsewhere.example/", srv.URL + "/admin/users"} {
		if _, err := c.Send(ctx, Baseline("active_xss", mustURL(t, raw))); !errors.Is(err, ErrOutOfScope) {
			t.Fatalf("%s: %v", raw, err)
		}
	}
	if hits.Load() != before {
		t.Fatal("an out-of-scope request reached the network")
	}
	if log.Count(OutcomeScope) != 2 {
		t.Fatalf("scope refusals not logged: %+v", log.Entries())
	}
	for _, e := range log.Entries() {
		if e.PayloadID == "xss.marker.tag" && (e.PayloadHash == "" || e.Param != "q" || e.Outcome != OutcomeSent) {
			t.Fatalf("log entry %+v", e)
		}
	}
}

func TestClientRefusesUncataloguedPayload(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("an uncatalogued payload was accepted")
		}
	}()
	Probe("active_xss", mustURL(t, "https://x.example/"), "q", Payload{ID: "evil", Module: "active_xss", In: InQuery, Value: "<script>"})
}

func TestClientWrongModulePayload(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("another module's payload was accepted")
		}
	}()
	p, _ := PayloadByID("sqli.quote")
	Probe("active_xss", mustURL(t, "https://x.example/"), "q", p)
}

func TestKillSwitchStopsBeforeTheNextRequest(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer srv.Close()
	k := &StaticKill{}
	c, log := newTestClient(t, srv, k, Limits{})
	u := mustURL(t, srv.URL+"/")
	if _, err := c.Send(context.Background(), Baseline("m", u)); err != nil {
		t.Fatal(err)
	}
	k.Kill()
	for range 3 {
		if _, err := c.Send(context.Background(), Baseline("m", u)); !errors.Is(err, ErrKilled) {
			t.Fatalf("after kill: %v", err)
		}
	}
	if hits.Load() != 1 || log.Count(OutcomeKilled) != 3 {
		t.Fatalf("hits=%d killed=%d", hits.Load(), log.Count(OutcomeKilled))
	}
}

func TestRedisKillFailsClosedAndSeesKeysWithinMaxAge(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	now := time.Unix(1000, 0)
	k := &RedisKill{RDB: rdb, ScanID: "s1", MaxAge: time.Second, now: func() time.Time { return now }}
	ctx := context.Background()
	if k.Killed(ctx) {
		t.Fatal("killed without a key")
	}
	_ = mr.Set(ScanKillKey("s1"), "1")
	if k.Killed(ctx) {
		t.Fatal("must cache 'not killed' for up to MaxAge")
	}
	now = now.Add(1100 * time.Millisecond)
	if !k.Killed(ctx) {
		t.Fatal("per-scan key not seen after MaxAge")
	}
	mr.Del(ScanKillKey("s1"))
	if !k.Killed(ctx) {
		t.Fatal("a kill is final for the scan")
	}
	// global key
	k2 := &RedisKill{RDB: rdb, ScanID: "s2"}
	_ = mr.Set(GlobalKillKey, "1")
	if !k2.Killed(ctx) {
		t.Fatal("global key not seen")
	}
	// unreadable switch = killed
	mr.Close()
	k3 := &RedisKill{RDB: redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 200 * time.Millisecond}), ScanID: "s3"}
	if !k3.Killed(ctx) {
		t.Fatal("redis unreachable must mean killed")
	}
}

func TestBudgets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	lim := DefaultLimits()
	lim.RPS, lim.ScanBudget, lim.ModuleBudget = 1000, 5, 3
	c, log := newTestClient(t, srv, &StaticKill{}, lim)
	u := mustURL(t, srv.URL+"/")
	for i := range 4 {
		_, err := c.Send(context.Background(), Baseline("a", u))
		if (i < 3) != (err == nil) {
			t.Fatalf("module budget at %d: %v", i, err)
		}
	}
	for i := range 3 {
		_, err := c.Send(context.Background(), Baseline("b", u))
		if (i < 2) != (err == nil) {
			t.Fatalf("scan budget at %d: %v", i, err)
		}
	}
	if c.Sent() != 5 || log.Count(OutcomeBudget) != 2 {
		t.Fatalf("sent=%d budget=%d", c.Sent(), log.Count(OutcomeBudget))
	}
}

func TestBreakerStopsOnConsecutive5xx(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c, log := newTestClient(t, srv, &StaticKill{}, Limits{})
	u := mustURL(t, srv.URL+"/")
	var err error
	for range 5 {
		_, err = c.Send(context.Background(), Baseline("m", u))
	}
	if !errors.Is(err, ErrBreaker) || hits.Load() != 3 || log.Count(OutcomeBreaker) != 2 {
		t.Fatalf("err=%v hits=%d breaker=%d", err, hits.Load(), log.Count(OutcomeBreaker))
	}
}

func TestBreakerStopsOnLongRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c, _ := newTestClient(t, srv, &StaticKill{}, Limits{})
	u := mustURL(t, srv.URL+"/")
	if _, err := c.Send(context.Background(), Baseline("m", u)); !errors.Is(err, ErrBreaker) {
		t.Fatalf("a 120s Retry-After must stop the scan: %v", err)
	}
	if _, err := c.Send(context.Background(), Baseline("m", u)); !errors.Is(err, ErrBreaker) {
		t.Fatalf("breaker must stay tripped: %v", err)
	}
}

func TestBreakerLatency(t *testing.T) {
	b := &breaker{lim: DefaultLimits()}
	for range 10 {
		if b.observe(200, 100*time.Millisecond) {
			t.Fatal("tripped at baseline latency")
		}
	}
	tripped := false
	for range 10 {
		tripped = b.observe(200, 400*time.Millisecond)
	}
	if !tripped {
		t.Fatal("4x latency must trip")
	}
}

func TestClientRefusesBlockedAddresses(t *testing.T) {
	log := &RequestLog{}
	// no AllowPrivateHosts: loopback is blocked by the probe guard at dial time
	c, err := NewClient(Options{Scope: mustScope(t, "http://127.0.0.1:9"), Kill: &StaticKill{}, Log: log, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Send(context.Background(), Baseline("m", mustURL(t, "http://127.0.0.1:9/"))); err == nil {
		t.Fatal("a loopback target must be refused")
	}
}

func TestRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	lim := DefaultLimits()
	lim.RPS = 5
	c, _ := newTestClient(t, srv, &StaticKill{}, lim)
	u := mustURL(t, srv.URL+"/")
	start := time.Now()
	for range 6 {
		if _, err := c.Send(context.Background(), Baseline("m", u)); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d < 900*time.Millisecond {
		t.Fatalf("6 requests at 5 rps took %v", d)
	}
}
