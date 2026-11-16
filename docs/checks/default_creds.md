# Check `default_creds` — unfinished setup and default passwords

- **Code:** `apps/scanner/internal/checks/default_creds.go` (+ `signatures.go`) · tests: `default_creds_test.go`
- **Category:** access · **i18n:** `checks.json` → `default_creds`

> **Passive only.** This check never submits credentials, never posts any form, never sends an
> `Authorization` header and never adds query parameters. A test (`TestDefaultCredsNeverSubmits`)
> fails if any request is not a plain GET without credentials or parameters. The probe client
> itself refuses every method other than GET/HEAD and every URL with `user:pass@`.

## What it detects and how

| Path | Finding key (severity) | `product` | Signature |
|---|---|---|---|
| `/wp-admin/install.php` | `installer_exposed` (critical) | WordPress | 200 + `wordpress` + (`id="setup"`, `weblog_title` or `install.php?step=1`) + **not** "already installed" |
| `/installation/` | `installer_exposed` (critical) | Joomla | 200 + `joomla` + (`web installer`, `jform[` or `id="installer"`) |
| `/core/install.php` | `installer_exposed` (critical) | Drupal | 200 + `drupal` + (`install-select-language-form`, `choose language`, `select an installation profile` or `set up database`) + **not** "already installed" |
| `/` | `installer_exposed` (critical) | Nextcloud | 200 + `nextcloud` + (`id="adminlogin"` or "create an **admin account**") |
| `/`, `/login` | `setup_wizard_exposed` (critical) | Jenkins | 200/403 + `jenkins` + (`unlock jenkins` or `initialAdminPassword`) |
| `/` | `default_login_product` (medium) | RabbitMQ Management | 200 + `RabbitMQ Management` (default `guest`/`guest`) |
| `/login` | `default_login_product` (medium) | Grafana | 200 + `grafanaBootData` (default `admin`/`admin`) |
| `/manager/html` | `default_login_product` (medium) | Apache Tomcat Manager | **401** + `WWW-Authenticate` realm `Tomcat Manager Application` (a header signature, not the status alone) |

All matching is case-insensitive. A response identical to the soft-404 baseline never counts.

Requests: `/`, `/login`, `/wp-admin/install.php`, `/installation/`, `/core/install.php`, `/manager/html` plus the shared baseline, so at most 7. `/` and the baseline are usually already cached from other checks.

## Evidence

Kind `http_response`; location is the probed URL. The payload has the status, content type, title and matched signature name. For Tomcat it shows the realm.

## Plain-language text (en)

- `installer_exposed`: "{product} installer is still reachable". If setup was never finished, anyone can finish it, create the admin account and take over the site. Fix: finish or remove the installer (for example, delete `installation/` in Joomla), restrict access, and re-scan.
- `default_login_product`: "{product} login is public; make sure the default password is changed". The text states that **we did not try to log in**.

## False-positive risk: low to medium

- Installer signatures are form markup specific to each product, and "already installed" pages are excluded (tested for WordPress and Drupal).
- `default_login_product` does not claim that the default password works (we never test it), only that the product is publicly reachable and known to ship with one. That is why it is medium, not critical.

## Why it is do-no-harm

At most 7 cached, rate-limited GETs. Installers and wizards are recognised from their first screen; we never advance a step. Login pages are recognised from markup or the auth realm; no password is ever sent.
