package checks

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// hqSite serves "/" as an HTML page with the given headers (and a
// Permissions-Policy and COOP unless the test sets them itself).
func hqSite(t *testing.T, headers map[string]string, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Permissions-Policy", "geolocation=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		for k, v := range headers {
			if v == "" {
				w.Header().Del(k)
				continue
			}
			w.Header().Add(k, v)
		}
		if body == "" {
			body = "<!doctype html><title>t</title>"
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestHeaderQualityClean(t *testing.T) {
	u := hqSite(t, map[string]string{"Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'none'"}, "")
	requireKeys(t, run(t, HeaderQuality{}, u))
}

func TestHeaderQualityNoCSPIsNotRepeated(t *testing.T) {
	requireKeys(t, run(t, HeaderQuality{}, hqSite(t, nil, "")))
}

func TestHeaderQualityUnsafeEval(t *testing.T) {
	cases := []struct {
		csp  string
		want bool
	}{
		{"default-src 'self'; script-src 'self' 'unsafe-eval'", true},
		{"default-src 'self' 'unsafe-eval'", true},
		{"script-src 'nonce-abc' 'strict-dynamic' 'unsafe-eval'; base-uri 'none'; object-src 'none'", true},
		{"script-src 'self' 'wasm-unsafe-eval'; object-src 'none'", false},
		// two policies: the stricter one blocks eval
		{"script-src 'self' 'unsafe-eval'; object-src 'none', script-src 'self'", false},
		// eval in default-src does not apply when script-src exists
		{"default-src 'self' 'unsafe-eval'; script-src 'self'; object-src 'none'", false},
	}
	for _, tc := range cases {
		fs := run(t, HeaderQuality{}, hqSite(t, map[string]string{"Content-Security-Policy": tc.csp}, ""))
		got := false
		for _, f := range fs {
			if f.FindingKey == "csp_unsafe_eval" {
				got = true
			}
		}
		if got != tc.want {
			t.Errorf("%q: csp_unsafe_eval=%v, want %v (%v)", tc.csp, got, tc.want, keysOf(fs))
		}
	}
}

func TestHeaderQualityBaseURI(t *testing.T) {
	requireKeys(t, run(t, HeaderQuality{}, hqSite(t, map[string]string{
		"Content-Security-Policy": "script-src 'nonce-r4nd0m' 'strict-dynamic'; object-src 'none'"}, "")), "csp_base_uri_missing")
	// no nonce/hash: a <base> cannot defeat a host allowlist any more than the allowlist allows
	requireKeys(t, run(t, HeaderQuality{}, hqSite(t, map[string]string{
		"Content-Security-Policy": "default-src 'self'; object-src 'none'"}, "")))
	requireKeys(t, run(t, HeaderQuality{}, hqSite(t, map[string]string{
		"Content-Security-Policy": "script-src 'sha256-AbC=' ; object-src 'none'; base-uri 'self'"}, "")))
	// hashes without strict-dynamic: not needed (CSP Evaluator)
	requireKeys(t, run(t, HeaderQuality{}, hqSite(t, map[string]string{
		"Content-Security-Policy": "script-src 'sha256-AbC='; object-src 'none'"}, "")))
	requireKeys(t, run(t, HeaderQuality{}, hqSite(t, map[string]string{
		"Content-Security-Policy": "script-src 'sha256-AbC=' 'strict-dynamic'; object-src 'none'"}, "")), "csp_base_uri_missing")
}

func TestHeaderQualityObjectSrc(t *testing.T) {
	requireKeys(t, run(t, HeaderQuality{}, hqSite(t, map[string]string{
		"Content-Security-Policy": "script-src 'self'; frame-ancestors 'none'"}, "")), "csp_object_src_unrestricted")
	requireKeys(t, run(t, HeaderQuality{}, hqSite(t, map[string]string{
		"Content-Security-Policy": "default-src https:; script-src 'self'"}, "")), "csp_object_src_unrestricted")
	requireKeys(t, run(t, HeaderQuality{}, hqSite(t, map[string]string{
		"Content-Security-Policy": "default-src 'self'"}, "")))
	// data: is not in Observatory's broad set
	requireKeys(t, run(t, HeaderQuality{}, hqSite(t, map[string]string{
		"Content-Security-Policy": "default-src 'self'; object-src data:"}, "")))
}

func TestHeaderQualityMetaCSP(t *testing.T) {
	body := `<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self' 'unsafe-eval'"></head></html>`
	requireKeys(t, run(t, HeaderQuality{}, hqSite(t, nil, body)), "csp_unsafe_eval")
}

func TestHeaderQualityPermissionsAndCOOP(t *testing.T) {
	csp := "default-src 'self'"
	requireKeys(t, run(t, HeaderQuality{}, hqSite(t, map[string]string{"Content-Security-Policy": csp, "Permissions-Policy": ""}, "")),
		"permissions_policy_missing")
	requireKeys(t, run(t, HeaderQuality{}, hqSite(t, map[string]string{"Content-Security-Policy": csp, "Cross-Origin-Opener-Policy": ""}, "")),
		"coop_missing")
}

func TestHeaderQualityNonDocument(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(srv.Close)
	requireKeys(t, run(t, HeaderQuality{}, srv.URL))
}

func TestHeaderQualityCacheableCookie(t *testing.T) {
	csp := "default-src 'self'"
	for _, tc := range []struct {
		cc   string
		want bool
	}{
		{"public, max-age=600", true},
		{"max-age=3600", true},
		{"s-maxage=60", true},
		{"public", true},
		{"private, max-age=600", false},
		{"no-store", false},
		{"max-age=0", false},
		{"no-cache, max-age=600", false},
		{"", false}, // no Cache-Control: not reported
	} {
		fs := run(t, HeaderQuality{}, hqSite(t, map[string]string{
			"Content-Security-Policy": csp, "Set-Cookie": "sid=s3cr3tvalue; Path=/; HttpOnly", "Cache-Control": tc.cc}, ""))
		if tc.want {
			requireKeys(t, fs, "cookie_response_cacheable")
			f := findKey(t, fs, "cookie_response_cacheable")
			if f.Params["cookie_name"] != "sid" {
				t.Errorf("params %v", f.Params)
			}
			if containsFold([]byte(f.Evidence.RedactedPayload), "s3cr3tvalue") {
				t.Fatal("cookie value leaked into evidence")
			}
		} else {
			requireKeys(t, fs)
		}
	}
}
