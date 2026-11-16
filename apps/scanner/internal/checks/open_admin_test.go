package checks

import (
	"net/http"
	"sync"
	"testing"
)

func TestOpenAdminPositive(t *testing.T) {
	srv := site(t, false, map[string]http.HandlerFunc{
		"/console": html(`<html><head><title>Console // Werkzeug Debugger</title></head><body><h1>Interactive Console</h1><script>var CONSOLE_MODE = true;</script><a href="?__debugger__=yes&cmd=resource">x</a></body></html>`),
		"/actuator": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/vnd.spring-boot.actuator.v3+json")
			_, _ = w.Write([]byte(`{"_links":{"self":{"href":"http://x/actuator","templated":false},"health":{"href":"http://x/actuator/health"}}}`))
		},
		"/actuator/env":          text(`{"activeProfiles":["prod"],"propertySources":[{"name":"systemEnvironment","properties":{"DB_PASSWORD":{"value":"******"}}}]}`),
		"/_profiler/":            html(`<html><head><title>Symfony Profiler</title></head><body class="sf-toolbar">profiler search</body></html>`),
		"/telescope":             html(`<html><head><title>Telescope - Acme</title></head><body><div id="telescope"></div><script>window.Telescope = {"path":"telescope"};</script></body></html>`),
		"/_debugbar/open":        text(`[{"id":"X1","datetime":"2026-01-01 00:00:00","utime":"1767225600.1","method":"GET","uri":"/","ip":"1.2.3.4"}]`),
		"/rails/info/properties": html(`<table><tr><td>Rails version</td><td>7.1.0</td></tr><tr><td>Ruby version</td><td>3.3.0</td></tr></table>`),
		"/phpmyadmin/":           html(`<html><head><title>phpMyAdmin</title><link rel="stylesheet" href="themes/pmahomme/css/theme.css"></head><body><form><input type="text" name="pma_username"><input type="password" name="pma_password"></form></body></html>`),
		"/adminer.php":           html(`<html><head><title>Login - Adminer</title></head><body><form><select name="auth[driver]"></select><input type="password" name="auth[password]"></form><a href="https://www.adminer.org/">Adminer</a></body></html>`),
		"/server-status":         html(`<html><head><title>Apache Status</title></head><body><h1>Apache Server Status for example.com (via 10.0.0.1)</h1></body></html>`),
		"/wp-login.php":          html(`<html><head><title>Log In &lsaquo; Acme &#8212; WordPress</title></head><body><form name="loginform" id="loginform"><input type="text" name="log" id="user_login"><input type="password" name="pwd"><input type="submit" id="wp-submit"></form></body></html>`),
	})
	fs := run(t, OpenAdmin{}, srv.URL)
	requireKeys(t, fs,
		"debug_console_exposed",
		"debug_endpoint_exposed", "debug_endpoint_exposed", "debug_endpoint_exposed", "debug_endpoint_exposed", "debug_endpoint_exposed", "debug_endpoint_exposed",
		"db_admin_exposed", "db_admin_exposed",
		"server_status_exposed",
		"admin_login_exposed",
	)
	if f := findKey(t, fs, "debug_console_exposed"); f.Params["product"] != "Werkzeug debugger" || f.Params["path"] != "/console" {
		t.Fatalf("params %v", f.Params)
	}
	if f := findKey(t, fs, "admin_login_exposed"); f.Params["path"] != "/wp-login.php" {
		t.Fatalf("params %v", f.Params)
	}
}

func TestOpenAdminGenericAdminLoginAndGrouping(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	login := `<html><head><title>Admin login</title></head><body><form><input type="password" name="p"></form></body></html>`
	srv := site(t, false, map[string]http.HandlerFunc{
		"/admin": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/admin/login", http.StatusFound)
		},
		"/admin/login": func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			hits[r.URL.Path]++
			mu.Unlock()
			html(login)(w, r)
		},
		"/administrator/": func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			hits[r.URL.Path]++
			mu.Unlock()
			html(login)(w, r)
		},
	})
	fs := run(t, OpenAdmin{}, srv.URL)
	requireKeys(t, fs, "admin_login_exposed")
	if fs[0].Params["path"] != "/admin" {
		t.Fatalf("params %v", fs[0].Params)
	}
	if hits["/administrator/"] != 0 {
		t.Fatal("probes in a matched group must be skipped")
	}
}

func TestOpenAdminNegative(t *testing.T) {
	// SPA soft-404: every path is 200 with the same shell.
	requireKeys(t, run(t, OpenAdmin{}, site(t, true, nil).URL))

	// SPA soft-404 whose shell contains a login form everywhere.
	shellWithLogin := `<!doctype html><html><head><title>Admin - Acme</title></head><body><input type="password"></body></html>`
	requireKeys(t, run(t, OpenAdmin{}, newCatchAll(t, shellWithLogin)))

	// Pages that mention the products but lack the signatures.
	srv2 := site(t, false, map[string]http.HandlerFunc{
		"/server-status": html(`<title>Status</title><p>All systems operational</p>`),
		"/phpmyadmin/":   html(`<p>We do not use phpMyAdmin here.</p>`),
		"/actuator":      text(`{"status":"UP"}`),
		"/console":       html(`<title>Console</title><p>Game console shop</p>`),
		"/admin":         html(`<title>Admin</title><p>Restricted</p>`),
		"/telescope":     html(`<title>Telescopes for sale</title>`),
	})
	requireKeys(t, run(t, OpenAdmin{}, srv2.URL))

	// Real signature but behind 403: not exposed.
	srv3 := site(t, false, map[string]http.HandlerFunc{
		"/server-status": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Apache Server Status for x"))
		},
	})
	requireKeys(t, run(t, OpenAdmin{}, srv3.URL))
}
