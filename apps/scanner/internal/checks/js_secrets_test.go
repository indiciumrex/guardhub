package checks

import (
	"net/http"
	"strings"
	"testing"

	"github.com/hksolutions/guardhub/apps/scanner/internal/labfixture"
)

func TestJSSecretsFound(t *testing.T) {
	gh := labfixture.MustSecret("github_pat", "jsk1")
	live := labfixture.MustSecret("stripe_live_secret", "jsk2")
	test := labfixture.MustSecret("stripe_test_secret", "jsk3")
	srv := site(t, false, map[string]http.HandlerFunc{
		"/":                html(`<!doctype html><title>Shop</title><script>Stripe("` + live + `")</script><script src="/static/app.js"></script><script src="/static/pay.js"></script>`),
		"/static/app.js":   js(`const cfg={token:"` + gh + `"};fetch("/api",{headers:{Authorization:"token "+cfg.token}})`),
		"/static/pay.js":   js(`var k="` + test + `";`),
		"/static/other.js": js(`never referenced: ` + gh),
	})
	fs := run(t, JSSecrets{}, srv.URL)
	requireKeys(t, fs, "secret_in_javascript", "secret_in_javascript", "test_secret_in_javascript")
	for _, f := range fs {
		for _, v := range []string{gh, live, test} {
			if strings.Contains(f.Evidence.RedactedPayload, v) || strings.Contains(f.Evidence.Location, v) {
				t.Fatalf("an unmasked secret in the evidence: %+v", f.Evidence)
			}
		}
	}
	if p := findKey(t, fs, "test_secret_in_javascript").Params; p["secret_type"] != "Stripe test-mode secret key" || !strings.HasSuffix(p["script"], "/static/pay.js") {
		t.Fatalf("test key params %v", p)
	}
}

func TestJSSecretsNegatives(t *testing.T) {
	srv := site(t, false, map[string]http.HandlerFunc{
		"/": html(`<!doctype html><title>Shop</title>
<script src="/static/app.js"></script><script src="https://cdn.example.test/x.js"></script>
<script>var stripe = Stripe("pk_live_51HxQ2bKzP7vTn4mYc8RdLs3wE9jUa6fGh1"); var password = "Password";</script>`),
		// placeholders and publishable keys only; the error page of a missing script is HTML
		"/static/app.js": js(`const t="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";const label={password:"Enter your password"};`),
	})
	requireKeys(t, run(t, JSSecrets{}, srv.URL))
}
