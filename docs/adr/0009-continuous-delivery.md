# ADR-0009: Continuous delivery: CI builds and signs, the server only pulls

- **Status:** accepted (founder, 2026-11-24: "ne benim makinem ne prod sunucu build yapar; sunucu yalnızca çeker")
- **Replaces:** the workstation build in `ops/deploy/deploy.sh` (images built locally, `docker save` over SSH)

## Context

Images were built on the founder's workstation and copied to the shared production host. Builds
there were slow and were killed for low memory. Building on the server would compete with other
projects for memory. Since 2026-11-24 the repository is public, so GitHub Actions minutes are
unlimited.

## Decision

1. **CI builds once, on main, after every gate.** In `ci.yml`, the job `release` runs only on a
   push to `main`. It `needs` every other job: lint, tests, secret scan, contracts, the full
   accuracy lab, the oracles and e2e. It builds `api`, `scanner` and `web` with plain
   `docker build`, with no `.env` in the context. It refuses an image whose filesystem contains an
   env file or a key. It pushes the images to `ghcr.io/<owner>/guardhub-<service>:<sha12>`, then
   signs each **digest** with Sigstore keyless signing (`ops/ci/release_images.sh`):
   - The signing identity is the GitHub OIDC token of `ci.yml@refs/heads/main`.
   - No signing key exists anywhere.
   - The job's `GITHUB_TOKEN` (packages: write) lives only for the length of the job.
2. **The server only pulls** (`ops/deploy/cd.sh`). Cron (`/etc/cron.d/guardhub-cd`) runs it every
   3 minutes. It needs no credential at all: it reads the public repository, the public API and
   public images anonymously. Nothing in GitHub can log in to the server. A deploy runs:
   - **A, B:** the main push run for that commit concluded `success` in every job, and the
     `release` job is among them.
   - **Release files:** git objects are fetched and archived, and git verifies every hash. The
     commit must descend from the serving release: no silent downgrade.
   - **Images:** each digest is accepted only when `cosign verify` proves the signature:
     - signed by `ci.yml@refs/heads/main`;
     - on a `push` trigger;
     - for exactly that commit (`--certificate-github-workflow-sha`).
     The OCI revision label must also match. Only then is the digest tagged
     `guardhub-<service>:<sha12>` for `guardhub-ctl.sh`.
   - **Probes** through nginx, every second, from before the switch until 30 s after the last
     gate.
   - **`guardhub-ctl.sh activate`** (unchanged): the pre-deploy backup, the expand-only migration,
     the idle colour, the health gate, then the nginx switch.
   - **Gates on the new serving colour, every deploy:**
     - **E:** health directly and through nginx. api and api-worker have no DNS and no route to a
       public IP. `github-egress` allows `api.github.com` and refuses `example.com`. Only
       loopback ports are published, and postgres/redis publish none. Every other project's
       containers are unchanged (names, ids, states).
     - **C:** `shared/.env` is `600 root`.
     - **F:** a self-scan with the new scanner and a fresh one-time token; a critical or high
       finding fails the gate.
     - **H:** a Sentry test event from api, api-worker, scanner and web is accepted.
     - **J:** the public pages answer 200, the Turkish locale renders, and the checks catalogue
       is served.
     - **G:** the pre-deploy dump is less than 1 h old and matches its manifest's sha256.
     - **K:** 0 failed probes over the whole window.
   - **Any red gate:** automatic `guardhub-ctl.sh rollback` (probed too), then **HALT**. No
     further deploy runs until a human reads the report and runs `cd.sh resume`. This puts "red
     gate: stop and report" into the mechanism itself.
3. **Module enabling is not automated by CD.** Switching on a passive module that passed its
   gate stays a separate, audited admin action (`registry.set_enabled`). Active modules stay off
   (ADR-0008, `ACTIVE_TESTING_APPROVED`).

## Consequences

- No build runs on the workstation or the server. A deploy costs the server one image pull of
  about 3 × 100–400 MB. `prune_images` keeps the images of the current release, the previous
  one and both colours.
- **The images are public** (the source is public, and images never contain secrets: see 1).
  If GHCR creates the packages private, their visibility must be set to public once, in the
  package settings. The alternative is a pull token on the server, which would be a new secret.
- **Supply chain:** a stolen GitHub account or token that can push images still cannot deploy.
  The server accepts only digests that `ci.yml` on main signed for the exact commit, and a
  commit on main goes through every gate first. Fulcio and Rekor (Sigstore) are trusted for
  this.
- **Gate J** is checked at HTTP level on every deploy. The full browser journey on the live site
  (`e2e/smoke`, an owned target with a planted fake secret) stays a manual check. It is still
  required after changes to the scan flow, because it needs a temporary vhost on the shared
  host. The same browser journey runs on every commit in CI (job `e2e`).
- **Gate I** (native Turkish review of new texts) stays a human gate. It is not a deploy check.
- The anonymous GitHub API allows 60 requests per hour per IP, and the host is shared. CD uses
  ETag-conditional requests (a 304 does not count) and runs every 3 minutes.
- **Manual trigger:** `ops/deploy/deploy.sh root@host [sha|status]` runs the same `cd.sh deploy`.
  The gates and the rollback are the same.
