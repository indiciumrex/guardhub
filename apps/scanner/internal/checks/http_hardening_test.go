package checks

import (
	"net/http"
	"strings"
	"testing"
)

func TestScriptWeaknesses(t *testing.T) {
	cases := []struct {
		csp  string
		weak string // "" = stops injected scripts
	}{
		{"default-src 'self'", ""},
		{"default-src 'none'; script-src 'self' https://cdn.example.com", ""},
		{"script-src 'self' 'unsafe-inline'", "script-src 'unsafe-inline'"},
		{"default-src 'self' 'unsafe-inline'", "default-src 'unsafe-inline'"},
		// a nonce or hash makes browsers ignore 'unsafe-inline' (CSP3 backwards-compat pattern)
		{"script-src 'nonce-R4nd0m' 'unsafe-inline'", ""},
		{"script-src 'sha256-AbC=' 'unsafe-inline' 'self'", ""},
		// 'strict-dynamic' ignores host and scheme sources (Google's recommended policy)
		{"script-src 'nonce-R4nd0m' 'strict-dynamic' 'unsafe-inline' https: http:; object-src 'none'; base-uri 'none'", ""},
		{"script-src 'self' https:", "script-src https:"},
		{"script-src *", "script-src *"},
		{"script-src 'self' data:", "script-src data:"},
		{"img-src *; style-src 'self'", "(no script-src / default-src)"},
		// not reported on purpose
		{"script-src 'self' 'unsafe-eval'", ""},
		{"default-src 'self'; img-src * data:", ""}, // img-src data: is harmless
		// a substring is not a source: '*.cdn.com' is a host source, report-uri http: is not script-src
		{"script-src 'self' *.cdn.example.com; report-uri http://r.example", ""},
		// case-insensitive directive names and duplicate directives (first wins)
		{"SCRIPT-SRC 'self'; script-src 'unsafe-inline'", ""},
	}
	for _, c := range cases {
		got := strings.Join(scriptWeaknesses(parseCSP(c.csp)), "; ")
		if got != c.weak {
			t.Errorf("%q: got %q, want %q", c.csp, got, c.weak)
		}
	}
}

func TestEnforcedPoliciesHeadersMetaAndReportOnly(t *testing.T) {
	h := http.Header{}
	h.Add("Content-Security-Policy", "script-src 'unsafe-inline', script-src 'self'")
	h.Add("Content-Security-Policy-Report-Only", "script-src *")
	body := []byte(`<html><head><META HTTP-EQUIV="content-security-policy" CONTENT="default-src &#39;self&#39;"></head></html>`)
	hp, mp := enforcedPolicies(h, body, true)
	if len(hp) != 2 || len(mp) != 1 {
		t.Fatalf("header=%d meta=%d", len(hp), len(mp))
	}
	if got := mp[0]["default-src"]; len(got) != 1 || got[0] != "'self'" {
		t.Fatalf("meta policy not decoded: %v", mp[0])
	}
	// two policies: scripts must pass both, so the strict one wins
	if r := weakestReasons(hp); r != nil {
		t.Fatalf("one strict policy is enough: %v", r)
	}
}

func hardeningSite(t *testing.T, h http.HandlerFunc) []string {
	t.Helper()
	srv := site(t, false, map[string]http.HandlerFunc{"/": h})
	return keysOf(run(t, HTTPHardening{}, srv.URL))
}

func TestHTTPHardeningCORS(t *testing.T) {
	reflect := func(creds bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if o := r.Header.Get("Origin"); o != "" {
				w.Header().Set("Access-Control-Allow-Origin", o)
				if creds {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		}
	}
	if ks := hardeningSite(t, reflect(true)); strings.Join(ks, ",") != "cors_any_origin_with_credentials" {
		t.Fatalf("reflected origin + credentials: %v", ks)
	}
	if ks := hardeningSite(t, reflect(false)); len(ks) != 0 {
		t.Fatalf("reflection without credentials exposes only public data: %v", ks)
	}
	wildcard := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true") // browsers refuse this combination
	}
	if ks := hardeningSite(t, wildcard); len(ks) != 0 {
		t.Fatalf("'*' never carries credentials: %v", ks)
	}
	nullOnly := func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == "null" {
			w.Header().Set("Access-Control-Allow-Origin", "null")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
	}
	if ks := hardeningSite(t, nullOnly); strings.Join(ks, ",") != "cors_null_origin_with_credentials" {
		t.Fatalf("null origin + credentials: %v", ks)
	}
}

func TestHTTPHardeningDocumentPolicies(t *testing.T) {
	page := func(headers map[string]string, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			for k, v := range headers {
				w.Header().Set(k, v)
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(body))
		}
	}
	html := "<!doctype html><html><head></head><body></body></html>"
	cases := []struct {
		name    string
		headers map[string]string
		body    string
		want    string
	}{
		{"strong policies", map[string]string{"Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"}, html, ""},
		{"no CSP is security_headers' finding", map[string]string{}, html, ""},
		{"weak CSP", map[string]string{"Content-Security-Policy": "script-src 'self' 'unsafe-inline'"}, html, "csp_ineffective"},
		{"weak CSP in meta", map[string]string{}, `<html><head><meta http-equiv="Content-Security-Policy" content="script-src *"></head></html>`, "csp_ineffective"},
		{"XFO ALLOW-FROM", map[string]string{"X-Frame-Options": "ALLOW-FROM https://partner.example"}, html, "xfo_ineffective"},
		{"XFO ALLOW-FROM but frame-ancestors set", map[string]string{"X-Frame-Options": "ALLOW-FROM https://p.example", "Content-Security-Policy": "default-src 'self'; frame-ancestors https://p.example"}, html, ""},
		{"XFO sameorigin lower-case", map[string]string{"X-Frame-Options": "sameorigin"}, html, ""},
		{"referrer unsafe-url", map[string]string{"Referrer-Policy": "unsafe-url"}, html, "referrer_policy_unsafe_url"},
		{"referrer fallback list ending safely", map[string]string{"Referrer-Policy": "unsafe-url, strict-origin-when-cross-origin"}, html, ""},
	}
	for _, c := range cases {
		got := strings.Join(hardeningSite(t, page(c.headers, c.body)), ",")
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	// a JSON API answer is not a document: no CSP/XFO/referrer judgement
	jsonAPI := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Security-Policy", "script-src *")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}
	if ks := hardeningSite(t, jsonAPI); len(ks) != 0 {
		t.Fatalf("JSON answer judged as a page: %v", ks)
	}
}

// The check never sends anything but GET, and never a cookie.
func TestHTTPHardeningSendsOnlyGETWithoutCookies(t *testing.T) {
	var methods []string
	srv := site(t, false, map[string]http.HandlerFunc{"/": func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		if r.Header.Get("Cookie") != "" {
			t.Errorf("a cookie was sent: %q", r.Header.Get("Cookie"))
		}
		w.Header().Set("Set-Cookie", "sid=x; HttpOnly")
	}})
	run(t, HTTPHardening{}, srv.URL)
	for _, m := range methods {
		if m != http.MethodGet {
			t.Fatalf("method %s sent", m)
		}
	}
	if len(methods) == 0 || len(methods) > 3 {
		t.Fatalf("requests: %v (want 1-3 GETs)", methods)
	}
}
