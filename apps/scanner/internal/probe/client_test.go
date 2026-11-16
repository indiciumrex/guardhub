package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testOptions allows the httptest loopback server and keeps tests fast.
func testOptions() Options {
	return Options{
		AllowPrivateHosts: []string{"127.0.0.1"},
		HostRPS:           1000,
		HostBurst:         100,
		BackoffBase:       time.Millisecond,
		Timeout:           2 * time.Second,
	}
}

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.8.9.10", "10.0.0.1", "172.16.5.4", "192.168.1.1",
		"169.254.169.254", "169.254.1.1", "100.64.0.1", "100.127.255.254",
		"0.0.0.0", "224.0.0.1", "255.255.255.255", "192.0.2.10", "198.18.0.1",
		"::1", "::", "fc00::1", "fd12:3456::1", "fe80::1", "ff02::1",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
		"64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "2002:7f00:1::1", "2001:db8::1",
		"::127.0.0.1", "fd00:ec2::254",
	}
	for _, s := range blocked {
		if !IsBlockedIP(netip.MustParseAddr(s)) {
			t.Errorf("%s must be blocked", s)
		}
	}
	allowed := []string{"93.184.216.34", "8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808", "100.128.0.1"}
	for _, s := range allowed {
		if IsBlockedIP(netip.MustParseAddr(s)) {
			t.Errorf("%s must be allowed", s)
		}
	}
}

func TestGuardBlocksLoopbackAtDialTime(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()

	opts := testOptions()
	opts.AllowPrivateHosts = nil
	c := New(opts)
	defer c.Close()
	_, err := c.Get(context.Background(), srv.URL+"/")
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("expected ErrBlockedAddress, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("blocked request reached the server")
	}

	// DNS name that resolves to loopback ("localhost") must also be refused at dial time.
	u, _ := url.Parse(srv.URL)
	_, err = c.Get(context.Background(), "http://localhost:"+u.Port()+"/")
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("expected ErrBlockedAddress for localhost, got %v", err)
	}
	if err := c.CheckHost(context.Background(), "127.0.0.1"); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("CheckHost: expected blocked, got %v", err)
	}
	if err := c.CheckHost(context.Background(), "localhost"); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("CheckHost localhost: expected blocked, got %v", err)
	}
}

func TestAllowlistBypassesGuardOnlyForListedHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer srv.Close()
	c := New(testOptions()) // allows "127.0.0.1" only
	defer c.Close()
	resp, err := c.Get(context.Background(), srv.URL+"/")
	if err != nil || string(resp.Body) != "ok" {
		t.Fatalf("allowlisted host should work: %v", err)
	}
	u, _ := url.Parse(srv.URL)
	if _, err := c.Get(context.Background(), "http://localhost:"+u.Port()+"/"); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("non-listed host must still be blocked, got %v", err)
	}
	if err := c.CheckHost(context.Background(), "127.0.0.1"); err != nil {
		t.Fatalf("CheckHost allowlisted: %v", err)
	}
}

type fakeResolver struct {
	ips map[string][]netip.Addr
	txt map[string][]string
}

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := f.ips[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if r, ok := f.txt[name]; ok {
		return r, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func TestCheckHostResolvesAndBlocksAnyPrivateAnswer(t *testing.T) {
	opts := testOptions()
	opts.Resolver = fakeResolver{ips: map[string][]netip.Addr{
		"public.test":   {netip.MustParseAddr("93.184.216.34")},
		"rebind.test":   {netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("10.1.2.3")},
		"metadata.test": {netip.MustParseAddr("169.254.169.254")},
	}}
	c := New(opts)
	if err := c.CheckHost(context.Background(), "public.test"); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"rebind.test", "metadata.test"} {
		if err := c.CheckHost(context.Background(), h); !errors.Is(err, ErrBlockedAddress) {
			t.Fatalf("%s: expected blocked, got %v", h, err)
		}
	}
	if err := c.CheckHost(context.Background(), "missing.test"); !errors.Is(err, ErrUnresolvableTarget) {
		t.Fatalf("expected unresolvable, got %v", err)
	}
	if c.RequestsUsed() != 0 {
		t.Fatal("CheckHost must not spend HTTP budget")
	}
}

func TestOnlyGetAndHeadAllowed(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	c := New(testOptions())
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions, "TRACE", "CONNECT"} {
		if _, err := c.Do(context.Background(), m, srv.URL+"/"); !errors.Is(err, ErrMethodNotAllowed) {
			t.Errorf("%s: expected ErrMethodNotAllowed, got %v", m, err)
		}
	}
	// Defence in depth: the transport itself refuses other methods.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/", strings.NewReader("x"))
	if res, err := c.hc.Do(req); !errors.Is(err, ErrMethodNotAllowed) {
		if res != nil {
			_ = res.Body.Close()
		}
		t.Errorf("transport must refuse POST, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("refused methods reached the server %d times", hits.Load())
	}
	if c.RequestsUsed() != 0 {
		t.Fatal("refused methods must not spend budget")
	}
	if _, err := c.Do(context.Background(), http.MethodHead, srv.URL+"/"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(context.Background(), http.MethodGet, srv.URL+"/"); err != nil {
		t.Fatal(err)
	}
}

func TestRequestShape(t *testing.T) {
	var gotUA, gotCookie, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA, gotCookie, gotAuth = r.UserAgent(), r.Header.Get("Cookie"), r.Header.Get("Authorization")
		http.SetCookie(w, &http.Cookie{Name: "s", Value: "1"})
	}))
	defer srv.Close()
	c := New(testOptions())
	if _, err := c.Get(context.Background(), srv.URL+"/a"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(context.Background(), srv.URL+"/b"); err != nil {
		t.Fatal(err)
	}
	if gotUA != UserAgent {
		t.Fatalf("UA = %q", gotUA)
	}
	if gotCookie != "" || gotAuth != "" {
		t.Fatal("client must never send cookies or credentials")
	}
	if _, err := c.Get(context.Background(), "http://user:pass@127.0.0.1/"); !errors.Is(err, ErrCredentialsInURL) {
		t.Fatalf("expected ErrCredentialsInURL, got %v", err)
	}
	if _, err := c.Get(context.Background(), "ftp://127.0.0.1/"); !errors.Is(err, ErrUnsupportedScheme) {
		t.Fatalf("expected ErrUnsupportedScheme, got %v", err)
	}
}

func TestRequestBudget(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	opts := testOptions()
	opts.MaxRequests = 5
	c := New(opts)
	for i := 0; i < 5; i++ {
		if _, err := c.Get(context.Background(), fmt.Sprintf("%s/p%d", srv.URL, i)); err != nil {
			t.Fatal(err)
		}
	}
	_, err := c.Get(context.Background(), srv.URL+"/over")
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("expected ErrBudgetExceeded, got %v", err)
	}
	if _, err := c.InspectTLS(context.Background(), "127.0.0.1", "443", TLSOptions{}); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("TLS inspection must also be budgeted, got %v", err)
	}
	if hits.Load() != 5 {
		t.Fatalf("server saw %d requests, want 5", hits.Load())
	}
	// Cached GETs do not cost budget.
	if _, err := c.Get(context.Background(), srv.URL+"/p0"); err != nil {
		t.Fatalf("cached GET should not need budget: %v", err)
	}
}

func TestRateLimitPerHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	opts := testOptions()
	opts.HostRPS = 20
	opts.HostBurst = 1
	c := New(opts)
	start := time.Now()
	for i := 0; i < 6; i++ {
		if _, err := c.Get(context.Background(), fmt.Sprintf("%s/r%d", srv.URL, i)); err != nil {
			t.Fatal(err)
		}
	}
	// 6 requests at 20 rps with burst 1 need at least 5 intervals of 50ms.
	if el := time.Since(start); el < 240*time.Millisecond {
		t.Fatalf("rate limit not applied: 6 requests took %v", el)
	}
}

func TestLimitersSharedAcrossClients(t *testing.T) {
	lim := NewLimiters(1, 1)
	if !lim.get("a.test").Allow() {
		t.Fatal("first token should be available")
	}
	if lim.get("a.test").Allow() {
		t.Fatal("same host must share one bucket")
	}
	if !lim.get("b.test").Allow() {
		t.Fatal("other hosts have their own bucket")
	}
	if lim.Len() != 2 {
		t.Fatalf("Len = %d", lim.Len())
	}
}

func TestRetriesOn503AndHonoursRetryAfter(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) < 3 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("fine"))
	}))
	defer srv.Close()
	c := New(testOptions())
	resp, err := c.Get(context.Background(), srv.URL+"/")
	if err != nil || resp.StatusCode != 200 || hits.Load() != 3 {
		t.Fatalf("resp=%v err=%v hits=%d", resp, err, hits.Load())
	}
}

func TestRetriesAreCapped(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c := New(testOptions())
	resp, err := c.Get(context.Background(), srv.URL+"/")
	if err != nil || resp.StatusCode != 429 {
		t.Fatalf("expected final 429 response, got %v %v", resp, err)
	}
	if hits.Load() != 3 { // 1 + max 2 retries
		t.Fatalf("hits = %d, want 3", hits.Load())
	}
}

func TestNoRetryOn500Or404(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := New(testOptions())
	if _, err := c.Get(context.Background(), srv.URL+"/"); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Fatalf("500 must not be retried, hits=%d", hits.Load())
	}
}

func TestParseRetryAfterCapped(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if d, ok := parseRetryAfter("3", now); !ok || d != 3*time.Second {
		t.Fatal(d, ok)
	}
	if d, ok := parseRetryAfter(now.Add(2*time.Second).Format(http.TimeFormat), now); !ok || d != 2*time.Second {
		t.Fatal(d, ok)
	}
	if _, ok := parseRetryAfter("soon", now); ok {
		t.Fatal("invalid value must be ignored")
	}
	// The cap is applied in roundTrip: a huge Retry-After must not stall the scan.
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			w.Header().Set("Retry-After", "3600")
			w.WriteHeader(http.StatusTooManyRequests)
		}
	}))
	defer srv.Close()
	opts := testOptions()
	opts.MaxRetryAfter = 50 * time.Millisecond
	c := New(opts)
	start := time.Now()
	if _, err := c.Get(context.Background(), srv.URL+"/"); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("Retry-After was not capped")
	}
}

func TestRedirects(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/r1", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/r2", http.StatusFound) })
	mux.HandleFunc("/r2", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/r3", http.StatusFound) })
	mux.HandleFunc("/r3", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/done", http.StatusFound) })
	mux.HandleFunc("/r0", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/r1", http.StatusFound) })
	mux.HandleFunc("/done", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("done")) })
	mux.HandleFunc("/away", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example/steal", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := New(testOptions())

	resp, err := c.Get(context.Background(), srv.URL+"/r1") // 3 hops: allowed
	if err != nil || string(resp.Body) != "done" || len(resp.Redirects) != 3 {
		t.Fatalf("3 redirects should be followed: %v %v", resp, err)
	}
	if _, err := c.Get(context.Background(), srv.URL+"/r0"); !errors.Is(err, ErrTooManyRedirects) {
		t.Fatalf("4 redirects must fail, got %v", err)
	}
	resp, err = c.Get(context.Background(), srv.URL+"/away")
	if err != nil || !resp.RedirectRefused || resp.StatusCode != http.StatusFound {
		t.Fatalf("cross-host redirect must be returned unfollowed: %+v %v", resp, err)
	}
	resp, err = c.GetNoFollow(context.Background(), srv.URL+"/r1")
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("GetNoFollow: %v %v", resp, err)
	}
}

func TestSameHostRedirect(t *testing.T) {
	p := func(s string) *url.URL { u, _ := url.Parse(s); return u }
	cases := []struct {
		from, to string
		ok       bool
	}{
		{"http://a.test/", "https://a.test/", true},
		{"http://a.test/", "https://a.test:443/x", true},
		{"https://a.test/", "https://a.test/x", true},
		{"https://a.test/", "http://a.test/", false},
		{"https://a.test/", "https://b.test/", false},
		{"https://a.test/", "https://www.a.test/", false},
		{"https://a.test/", "https://a.test:8443/", false},
		{"http://a.test/", "javascript:alert(1)", false},
	}
	for _, tc := range cases {
		if got := sameHostRedirect(p(tc.from), p(tc.to)); got != tc.ok {
			t.Errorf("%s -> %s: got %v want %v", tc.from, tc.to, got, tc.ok)
		}
	}
}

func TestBodyCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", 300<<10)))
	}))
	defer srv.Close()
	c := New(testOptions())
	resp, err := c.Get(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Body) != DefaultBodyCap || !resp.Truncated {
		t.Fatalf("body len %d truncated %v", len(resp.Body), resp.Truncated)
	}
}

func TestPerRequestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(3 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	opts := testOptions()
	opts.Timeout = 100 * time.Millisecond
	opts.MaxRetries = -1
	c := New(opts)
	start := time.Now()
	if _, err := c.Get(context.Background(), srv.URL+"/"); err == nil {
		t.Fatal("expected timeout error")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("timeout not enforced")
	}
}

func TestLookupTXT(t *testing.T) {
	opts := testOptions()
	opts.Resolver = fakeResolver{txt: map[string][]string{"_guardhub.a.test": {"guardhub-verify=abc"}}}
	opts.MaxRequests = 1
	c := New(opts)
	got, err := c.LookupTXT(context.Background(), "_guardhub.a.test.")
	if err != nil || len(got) != 1 || got[0] != "guardhub-verify=abc" {
		t.Fatalf("got %v %v", got, err)
	}
	if _, err := c.LookupTXT(context.Background(), "a.test"); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("DNS lookups are budgeted, got %v", err)
	}
}
