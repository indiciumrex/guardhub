package checks

import (
	"net/http"
	"sync"
	"testing"
)

const wpInstallForm = `<!DOCTYPE html><html><head><title>WordPress &rsaquo; Installation</title></head><body class="wp-core-ui">
<form id="setup" method="post" action="install.php?step=1"><select name="language" id="language"></select></form></body></html>`

func TestDefaultCredsPositive(t *testing.T) {
	srv := site(t, false, map[string]http.HandlerFunc{
		"/wp-admin/install.php": html(wpInstallForm),
		"/installation/":        html(`<html><head><title>Joomla! Web Installer</title></head><body><form><input name="jform[site_name]"></form></body></html>`),
		"/core/install.php":     html(`<html><head><title>Choose language | Drupal</title></head><body><form id="install-select-language-form"></form></body></html>`),
		"/login":                html(`<html><head><title>Grafana</title></head><body><script>window.grafanaBootData = {"settings":{}};</script></body></html>`),
		"/manager/html": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
			w.WriteHeader(http.StatusUnauthorized)
		},
		"/": html(`<html><head><title>Sign in [Jenkins]</title></head><body><h1>Unlock Jenkins</h1><p>/var/jenkins_home/secrets/initialAdminPassword</p></body></html>`),
	})
	fs := run(t, DefaultCreds{}, srv.URL)
	requireKeys(t, fs, "installer_exposed", "installer_exposed", "installer_exposed", "setup_wizard_exposed",
		"default_login_product", "default_login_product")
	products := map[string]string{}
	for _, f := range fs {
		products[f.Params["product"]] = f.Params["path"]
	}
	want := map[string]string{"WordPress": "/wp-admin/install.php", "Joomla": "/installation/", "Drupal": "/core/install.php",
		"Jenkins": "/", "Grafana": "/login", "Apache Tomcat Manager": "/manager/html"}
	for p, path := range want {
		if products[p] != path {
			t.Errorf("product %s: path %q, want %q (all: %v)", p, products[p], path, products)
		}
	}
}

func TestDefaultCredsNeverSubmits(t *testing.T) {
	var mu sync.Mutex
	var bad []string
	guard := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" || r.ContentLength > 0 || r.URL.RawQuery != "" {
				mu.Lock()
				bad = append(bad, r.Method+" "+r.URL.String())
				mu.Unlock()
			}
			next(w, r)
		}
	}
	srv2 := site(t, false, map[string]http.HandlerFunc{
		"/wp-admin/install.php": guard(html(wpInstallForm)),
		"/manager/html": guard(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
			w.WriteHeader(http.StatusUnauthorized)
		}),
		"/login": guard(html(`<script>window.grafanaBootData={}</script>`)),
		"/":      guard(html(`<title>home</title>`)),
	})
	run(t, DefaultCreds{}, srv2.URL)
	if len(bad) > 0 {
		t.Fatalf("default_creds sent non-passive requests: %v", bad)
	}
}

func TestDefaultCredsNegative(t *testing.T) {
	requireKeys(t, run(t, DefaultCreds{}, site(t, true, nil).URL))

	srv := site(t, false, map[string]http.HandlerFunc{
		// WordPress already installed.
		"/wp-admin/install.php": html(`<html><head><title>WordPress &rsaquo; Installation</title></head><body><h1>Already Installed</h1><p>You appear to have already installed WordPress.</p></body></html>`),
		// Drupal already installed.
		"/core/install.php": html(`<title>Drupal already installed | Drupal</title><p>Drupal already installed</p><p>Choose language</p>`),
		// Generic login, not a known product.
		"/login": html(`<title>Login</title><form><input type="password"></form>`),
		// 401 with an unrelated realm.
		"/manager/html": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			w.WriteHeader(http.StatusUnauthorized)
		},
		// Jenkins after setup (no wizard).
		"/": html(`<title>Dashboard [Jenkins]</title>`),
	})
	requireKeys(t, run(t, DefaultCreds{}, srv.URL))
}

// Validation lab (Grafana 11): a single-page app answers every path with the
// same shell, so its login equals the soft-404 baseline. A product-specific
// marker on that shell still proves the product; a generic catch-all does not.
func TestDefaultCredsSPAProductShell(t *testing.T) {
	grafana := newCatchAll(t, `<!doctype html><html><head><title>Grafana</title></head><body><script>window.grafanaBootData = {"settings":{}};</script></body></html>`)
	fs := run(t, DefaultCreds{}, grafana)
	f := findKey(t, fs, "default_login_product")
	if f.Params["product"] != "Grafana" || f.Params["path"] != "/login" {
		t.Fatalf("grafana: %+v", f.Params)
	}
	if len(fs) != 1 {
		t.Fatalf("only the Grafana probe may match on a Grafana shell, got %d findings", len(fs))
	}
	other := newCatchAll(t, `<!doctype html><html><head><title>Shop</title></head><body><div id="app">login</div></body></html>`)
	if fs := run(t, DefaultCreds{}, other); len(fs) != 0 {
		t.Fatalf("a generic SPA shell must not match anything: %+v", fs)
	}
}
