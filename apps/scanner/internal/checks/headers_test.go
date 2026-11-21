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

// Validation lab finding (WebGoat): an origin root that answers an empty 404,
// or an API that answers JSON, is not a page; document headers don't apply.
func TestSecurityHeadersIgnoreNonDocuments(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"empty 404": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) },
		"json api": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		},
	} {
		srv := site(t, false, map[string]http.HandlerFunc{"/": h})
		for _, f := range run(t, SecurityHeaders{}, srv.URL) {
			if f.FindingKey == "csp_missing" || f.FindingKey == "nosniff_missing" || f.FindingKey == "clickjacking_unprotected" {
				t.Errorf("%s: document finding %s on a non-document", name, f.FindingKey)
			}
		}
	}
	// still a document: an HTML 404 page, and HTML served without a Content-Type
	srv := site(t, false, map[string]http.HandlerFunc{"/": func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<!doctype html><title>Not found</title>"))
	}})
	requireKeys(t, run(t, SecurityHeaders{}, srv.URL), "csp_missing", "nosniff_missing", "clickjacking_unprotected")
}

// Validation lab: a CSP delivered in <meta> is a CSP (static hosts use it).
func TestSecurityHeadersMetaCSPCounts(t *testing.T) {
	srv := site(t, false, map[string]http.HandlerFunc{"/": func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		_, _ = w.Write([]byte(`<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'"></head><body></body></html>`))
	}})
	for _, f := range run(t, SecurityHeaders{}, srv.URL) {
		if f.FindingKey == "csp_missing" {
			t.Fatal("a <meta> CSP was reported as missing")
		}
	}
	// frame-ancestors in <meta> is ignored by browsers: still clickjackable without XFO
	noXFO := site(t, false, map[string]http.HandlerFunc{"/": func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'; frame-ancestors 'none'"></head></html>`))
	}})
	findKey(t, run(t, SecurityHeaders{}, noXFO.URL), "clickjacking_unprotected")
}

// CSRF double-submit cookies are readable by JS by design; other flags still apply.
func TestSecurityHeadersCSRFCookieNeedsNoHttpOnly(t *testing.T) {
	srv := site(t, false, map[string]http.HandlerFunc{"/": func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", "XSRF-TOKEN=abcdefghij0123456789; Path=/; SameSite=Lax")
		w.Header().Add("Set-Cookie", "csrftoken=abcdefghij0123456789; Path=/")
		_, _ = w.Write([]byte("<html></html>"))
	}})
	var csrftoken bool
	for _, f := range run(t, SecurityHeaders{}, srv.URL) {
		if f.FindingKey != "cookie_flags_missing" {
			continue
		}
		if f.Params["cookie_name"] == "XSRF-TOKEN" {
			t.Fatalf("XSRF-TOKEN must not need HttpOnly: %v", f.Params)
		}
		if f.Params["cookie_name"] == "csrftoken" {
			csrftoken = true
			if f.Params["missing_flags"] != "SameSite" {
				t.Fatalf("csrftoken still needs SameSite, but not HttpOnly: %v", f.Params)
			}
		}
	}
	if !csrftoken {
		t.Fatal("csrftoken without SameSite must still be reported")
	}
}
