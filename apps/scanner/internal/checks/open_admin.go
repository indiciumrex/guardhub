package checks

// open_admin: finds debug consoles, framework debug endpoints, database
// admin tools, server status pages and admin login pages that are reachable
// from the internet. Each hit needs a product-specific content signature;
// a 200 status alone never counts. Only GETs; no form is ever submitted.

import (
	"context"
	"regexp"
	"strings"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
)

// OpenAdmin implements the open_admin check.
type OpenAdmin struct{}

// ID implements Check.
func (OpenAdmin) ID() string { return evidence.CheckOpenAdmin }

var passwordInputRe = regexp.MustCompile(`(?i)<input[^>]+type\s*=\s*["']?password`)

// openAdminProbes is the fixed, ordered probe list (see docs/checks/open_admin.md).
var openAdminProbes = []pathProbe{
	{path: "/console", key: "debug_console_exposed", product: "Werkzeug debugger",
		match: status200Where(`"Werkzeug" + "__debugger__"|"Interactive Console"`,
			bodyAll("werkzeug"), bodyAny("__debugger__", "interactive console"))},
	{path: "/actuator", key: "debug_endpoint_exposed", product: "Spring Boot Actuator",
		match: status200All(`"_links"`, `/actuator`)},
	{path: "/actuator/env", key: "debug_endpoint_exposed", product: "Spring Boot Actuator", group: "actuator-env",
		match: status200All(`"propertySources"`, `"activeProfiles"`)},
	{path: "/_profiler/", key: "debug_endpoint_exposed", product: "Symfony Profiler",
		match: status200Where(`"Symfony Profiler"|"sf-toolbar"`, bodyAny("symfony profiler", "sf-toolbar"), bodyAll("profiler"))},
	{path: "/telescope", key: "debug_endpoint_exposed", product: "Laravel Telescope",
		match: status200All("window.Telescope")},
	{path: "/_debugbar/open", key: "debug_endpoint_exposed", product: "Laravel Debugbar",
		match: status200All(`"utime"`, `"datetime"`, `"uri"`)},
	{path: "/rails/info/properties", key: "debug_endpoint_exposed", product: "Rails info page",
		match: status200All("Rails version", "Ruby version")},
	// "/" first: the official docker image serves phpMyAdmin at the origin root
	// (its own site, e.g. pma.example.com). The root GET is cached.
	{path: "/", key: "db_admin_exposed", product: "phpMyAdmin", match: phpMyAdminMatch},
	{path: "/phpmyadmin/", key: "db_admin_exposed", product: "phpMyAdmin", match: phpMyAdminMatch},
	{path: "/phpMyAdmin/", key: "db_admin_exposed", product: "phpMyAdmin", match: phpMyAdminMatch},
	{path: "/pma/", key: "db_admin_exposed", product: "phpMyAdmin", match: phpMyAdminMatch},
	{path: "/adminer.php", key: "db_admin_exposed", product: "Adminer",
		match: status200Where(`"Adminer" + "auth[driver]"|"adminer.org"`, bodyAll("adminer"), bodyAny("auth[driver]", "adminer.org"))},
	{path: "/adminer/", key: "db_admin_exposed", product: "Adminer",
		match: status200Where(`"Adminer" + "auth[driver]"|"adminer.org"`, bodyAll("adminer"), bodyAny("auth[driver]", "adminer.org"))},
	{path: "/server-status", key: "server_status_exposed", group: "server-status",
		match: status200All("Apache Server Status for")},
	{path: "/nginx_status", key: "server_status_exposed", group: "server-status",
		match: status200All("Active connections:", "server accepts handled requests")},
	// Prometheus metrics (internal counters, routes, versions) open to anyone.
	{path: "/metrics", key: "server_status_exposed", group: "prometheus-metrics", match: prometheusMatch},
	{path: "/wp-login.php", key: "admin_login_exposed", group: "admin-login",
		match: func(r *probe.Response) (string, bool) {
			// id="loginform" only: the installer page also has user_login + a password
			// field (validation lab: a mid-install site was reported as "login exposed").
			if r.StatusCode == 200 && passwordInputRe.Match(r.Body) && bodyAll(`id="loginform"`)(r.Body) {
				return `WordPress login form ("loginform" + password field)`, true
			}
			return "", false
		}},
	{path: "/admin", key: "admin_login_exposed", group: "admin-login", match: adminLoginMatch},
	{path: "/admin/login", key: "admin_login_exposed", group: "admin-login", match: adminLoginMatch},
	{path: "/administrator/", key: "admin_login_exposed", group: "admin-login", match: adminLoginMatch},
}

func phpMyAdminMatch(r *probe.Response) (string, bool) {
	return status200Where(`"phpMyAdmin" + login form markers`,
		bodyAll("phpmyadmin"), bodyAny("pma_username", "pma_password", "pmahomme", "phpmyadmin.css", "<title>phpmyadmin"))(r)
}

// installerTitleRe: page titles of install/setup wizards.
var installerTitleRe = regexp.MustCompile(`(?i)\b(install|installation|installer|setup)\b`)

// adminLoginMatch: an HTML page with a password field that is about an
// admin area (final URL or page text mentions "admin").
func adminLoginMatch(r *probe.Response) (string, bool) {
	if r.StatusCode != 200 || !passwordInputRe.Match(r.Body) {
		return "", false
	}
	// An install/setup wizard has a password field too (choose the admin
	// password) but is not a login: default_creds reports installers.
	// (Validation lab: WordPress mid-install, /admin -> /wp-admin/install.php.)
	if installerTitleRe.MatchString(pageTitle(r.Body)) {
		return "", false
	}
	if strings.Contains(strings.ToLower(r.URL.Path), "admin") || containsFold([]byte(pageTitle(r.Body)), "admin") {
		return `password field on an admin page`, true
	}
	return "", false
}

// Run implements Check.
func (c OpenAdmin) Run(ctx context.Context, t Target) ([]evidence.Finding, error) {
	return runProbes(ctx, c.ID(), t, openAdminProbes)
}

// prometheusMatch: the Prometheus/OpenMetrics text exposition format, served
// as plain text (an HTML page that merely mentions "# HELP" does not count).
func prometheusMatch(r *probe.Response) (string, bool) {
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if r.StatusCode != 200 || !(strings.HasPrefix(ct, "text/plain") || strings.Contains(ct, "openmetrics")) {
		return "", false
	}
	if bodyAll("# HELP ", "# TYPE ")(r.Body) {
		return `Prometheus metrics ("# HELP" + "# TYPE" lines, text/plain)`, true
	}
	return "", false
}
