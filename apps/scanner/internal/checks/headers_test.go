package checks

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeadersAllMissingHTTP(t *testing.T) {
	srv := site(t, false, map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Add("Set-Cookie", "session=abcdefghijklmnop1234; Path=/")
			w.Header().Add("Set-Cookie", "prefs=dark; Path=/; HttpOnly; SameSite=Lax")
			_, _ = w.Write([]byte("<html></html>"))
		},
	})
	fs := run(t, SecurityHeaders{}, srv.URL)
	// http: no HSTS findings; Secure is not required on http.
	requireKeys(t, fs, "csp_missing", "nosniff_missing", "clickjacking_unprotected", "cookie_flags_missing")
	ck := findKey(t, fs, "cookie_flags_missing")
	if ck.Params["cookie_name"] != "session" || ck.Params["missing_flags"] != "HttpOnly, SameSite" {
		t.Fatalf("cookie params %v", ck.Params)
	}
	if strings.Contains(ck.Evidence.RedactedPayload, "abcdefghijklmnop1234") || !strings.Contains(ck.Evidence.RedactedPayload, "****1234") {
		t.Fatalf("cookie value must be masked: %q", ck.Evidence.RedactedPayload)
	}
}

func TestSecurityHeadersHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(siteHandler(false, map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Strict-Transport-Security", "max-age=3600; includeSubDomains")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Add("Set-Cookie", "sid=0123456789abcdef; Path=/; HttpOnly; SameSite=Strict")
		},
	}))
	defer srv.Close()
	fs := run(t, SecurityHeaders{}, srv.URL)
	requireKeys(t, fs, "hsts_weak", "cookie_flags_missing")
	if f := findKey(t, fs, "hsts_weak"); f.Params["max_age"] != "3600" {
		t.Fatalf("max_age %v", f.Params)
	}
	if f := findKey(t, fs, "cookie_flags_missing"); f.Params["missing_flags"] != "Secure" {
		t.Fatalf("missing flags %v", f.Params)
	}
}

func TestSecurityHeadersHSTSMissingOnHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}))
	defer srv.Close()
	requireKeys(t, run(t, SecurityHeaders{}, srv.URL), "hsts_missing")
}

func TestSecurityHeadersAllGood(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Add("Set-Cookie", "sid=0123456789abcdef; Path=/; Secure; HttpOnly; SameSite=Lax")
	}))
	defer srv.Close()
	requireKeys(t, run(t, SecurityHeaders{}, srv.URL))
}

func TestSecurityHeadersCrossHostRedirectOnlyChecksTransport(t *testing.T) {
	srv := site(t, false, map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://www.example.com/", http.StatusMovedPermanently)
		},
	})
	requireKeys(t, run(t, SecurityHeaders{}, srv.URL))
}
