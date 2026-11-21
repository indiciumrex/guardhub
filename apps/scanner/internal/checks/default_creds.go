package checks

// default_creds: PASSIVE ONLY. It never submits credentials, never posts a
// form and never sends an Authorization header. It recognises, from a single
// GET each, installers and setup wizards left reachable (anyone could finish
// the setup and become admin) and well-known products that ship with default
// credentials (by their login page or HTTP auth realm).

import (
	"context"
	"regexp"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
)

// DefaultCreds implements the default_creds check.
type DefaultCreds struct{}

// ID implements Check.
func (DefaultCreds) ID() string { return evidence.CheckDefaultCreds }

var tomcatRealmRe = regexp.MustCompile(`(?i)realm\s*=\s*"?Tomcat Manager Application`)

// defaultCredsProbes is the fixed, ordered probe list (see docs/checks/default_creds.md).
// "/" and "/login" appear several times: the probe client caches GETs, so
// each path costs one request.
var defaultCredsProbes = []pathProbe{
	{path: "/wp-admin/install.php", key: "installer_exposed", product: "WordPress",
		match: status200Where(`WordPress install form ("setup"/"weblog_title"), not "already installed"`,
			bodyAll("wordpress"), bodyAny(`id="setup"`, "weblog_title", "install.php?step=1"), bodyNone("already installed"))},
	{path: "/installation/", key: "installer_exposed", product: "Joomla",
		match: status200Where(`Joomla web installer ("Joomla" + "Web Installer"/"jform[")`,
			bodyAll("joomla"), bodyAny("web installer", "jform[", `id="installer"`))},
	{path: "/core/install.php", key: "installer_exposed", product: "Drupal",
		match: status200Where(`Drupal installer form, not "already installed"`,
			bodyAll("drupal"), bodyAny("install-select-language-form", "choose language", "select an installation profile", "set up database"),
			bodyNone("already installed"))},
	{path: "/", key: "installer_exposed", product: "Nextcloud",
		match: status200Where(`Nextcloud first-run form ("adminlogin")`,
			bodyAll("nextcloud"), bodyAny(`id="adminlogin"`, "create an <strong>admin account</strong>"))},
	{path: "/", key: "setup_wizard_exposed", product: "Jenkins", group: "jenkins",
		match: jenkinsMatch},
	{path: "/login", key: "setup_wizard_exposed", product: "Jenkins", group: "jenkins",
		match: jenkinsMatch},
	{path: "/", key: "default_login_product", product: "RabbitMQ Management",
		match: status200All("RabbitMQ Management")},
	{path: "/login", key: "default_login_product", product: "Grafana",
		match: status200All("grafanaBootData"), spaShell: true},
	{path: "/manager/html", key: "default_login_product", product: "Apache Tomcat Manager",
		match: func(r *probe.Response) (string, bool) {
			if r.StatusCode == 401 && tomcatRealmRe.MatchString(r.Header.Get("WWW-Authenticate")) {
				return `WWW-Authenticate realm "Tomcat Manager Application"`, true
			}
			return "", false
		}},
}

func jenkinsMatch(r *probe.Response) (string, bool) {
	// The unlock page is served with 200 (or 403 on some versions).
	if r.StatusCode != 200 && r.StatusCode != 403 {
		return "", false
	}
	if bodyAny("unlock jenkins", "initialAdminPassword")(r.Body) && containsFold(r.Body, "jenkins") {
		return `"Unlock Jenkins" setup wizard`, true
	}
	return "", false
}

// Run implements Check.
func (c DefaultCreds) Run(ctx context.Context, t Target) ([]evidence.Finding, error) {
	return runProbes(ctx, c.ID(), t, defaultCredsProbes)
}
