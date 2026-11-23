# Validation lab (`test_corpus/`)

The lab measures how accurate each check is: **true positives, false positives and false
negatives against known targets**, so that no check is switched on without a measured
precision and recall (`docs/accuracy/`). Run it with:

```bash
bash test_corpus/run.sh     # fresh lab, measure, write docs/accuracy + packages/shared/accuracy.json, tear down
```

## Safety

- **Deliberately vulnerable software.** Everything runs on the `lab` docker network, which is
  `internal: true`: no route to the internet, nothing published to the host. Never deploy any
  of it.
- The scanner runs as `scanner lab`, the production checks, probe client and request budget,
  but it **refuses any origin that is not a `*.lab.test` host on its private-host allowlist**
  (`queue.ScanLabOrigin`). `.test` is a reserved TLD that never resolves publicly, so a wrong
  manifest cannot make the lab scan a real site. There is no other path that scans without an
  ownership proof.
- Certificates (`cmd/labpki`) and the leaky site's secrets (`leaky-init.sh`) are generated at
  every start. Nothing secret-shaped is committed.
- Third-party images are pinned by digest.
- Provider zones such as `s3.amazonaws.com` and `azurewebsites.net` exist only inside the lab's
  resolver (`dns-res`), on a network with no internet. They let the curated provider list be
  measured as shipped, with no lab-only suffixes.

## Ground truth (the oracle)

`manifests/<target>.yaml` says, for one target, which findings each scored check MUST report
(`expect`, each with a `why`), and optionally which it may report (`tolerate`, also with a
`why`). Anything else a check reports there is a **false positive**. Ground truth is written
from the lab's own configuration (synthetic targets) or from behaviour verified by hand with
curl/openssl inside the lab, **never from scanner output**. When a run disagrees with a
manifest, the disagreement is investigated: either the check is wrong (fix the check, add a
regression test) or the manifest is wrong (fix it and say so in the `why`).

`outside: true` marks a real issue beyond what a check declares it covers (e.g. a product not
in its fixed catalogue). Missing it still counts: it lowers "Recall (all)", but not the recall
the gate uses. Every use names the declared scope.

**Header oracle (`oracles/headers/`).** `header_quality` truth comes from Mozilla's HTTP
Observatory scanner and Google's CSP Evaluator, versions locked in `package-lock.json`, run
unmodified inside the lab network (the Dockerfile has the command). It prints, per origin, the
keys the tools find; the `hq-*` expectations cite that output. The same oracle gives the
`cookie_depth` truth: every `Set-Cookie` header goes through tough-cookie 5.1.2 (Observatory's cookie
jar, prefix security "strict"), and the `ck-*` expectations cite what it refused or stored. Its only change to the tools'
setup: an empty HSTS preload list, which the Observatory loads at start-up but its CSP
verdicts do not read. CI's `header-truth` job runs `oracles/headers/run.sh` on every
push: light targets together, then each third-party app alone (start, wait, measure,
remove), and `compare.py` fails the job when any manifest disagrees with the oracle or a
target could not be read.

**DNS oracle (`oracles/dns/`).** `dns_depth` truth comes from BIND's `dig` and `delv` (DNSSEC
validated with the parent's DS records as the only trust anchor), OpenSSL (DKIM key sizes) and
curl (the MTA-STS policy, lab CA, no redirects), run unmodified in the lab network;
`oracle_dns.py` applies the RFC rules to their output and compares the result with every
manifest. CI's `dns-truth` job runs `oracles/dns/run.sh` (DNS stand-ins and light fronts only)
and fails on any disagreement. Names served by Docker's resolver rather than a lab zone answer
SERVFAIL for most record types: the oracle lists them as "no DNS data", where neither it nor the
check may derive a finding.

## Targets

| Target | What it is | Main use |
|---|---|---|
| `clean` | nginx, hardened (TLS 1.2+, full chain, strict headers, flagged cookie) | false positives: must find nothing |
| `tls-*` | `clean`, wrong in exactly one TLS property each | `tls_cert` |
| `td-*` | `clean`, wrong in one certificate property (no SCT, SHA-1, 825-day lifetime, OCSP stapled / not stapled, HSTS preload ineligible) | `tls_depth` (truth: testssl.sh 3.2) |
| `hq-*` | `clean`, wrong in one browser-policy header (`nginx/hq.conf`); `hq-wasm` and `hq-private` are look-alike negatives | `header_quality` (truth: `oracles/headers`) |
| `dd-*` | own zones under `dd.lab.test` (`dns/dd/`), signed at lab start by `labdns`; `dd-good` with one DNS or e-mail transport difference each; `dd-good`, `dd-www`, `dd-nomail` are negatives | `dns_depth` (truth: `oracles/dns`) |
| `ck-*` | `clean`, different only in its `Set-Cookie` header (`nginx/ck.conf`); `ck-analytics` and `ck-foreign` are look-alike negatives | `cookie_depth` (truth: tough-cookie in `oracles/headers`) |
| `leaky` | a careless static deployment (.env, .git, .aws, autoindex) | `exposed_env`, `info_leak` |
| `juice-shop` | OWASP Juice Shop (SPA: 200 for every path) | soft-404 trap, `info_leak`, `open_admin` |
| `dvwa` | DVWA + MariaDB | headers, versions, cookies |
| `webgoat` | OWASP WebGoat (empty 404 at `/`) | non-document trap |
| `phpmyadmin`, `grafana`, `wordpress`, `drupal` | real products in default setups | `open_admin`, `default_creds` |
| `rp-*` | GitHub repositories served by the GitHub/OSV stand-in (`labrepo`, `github.lab.test` + `osv.lab.test`) from `repos/<target>/`; OSV answers replayed from `osv/` | `dependency_vulns` (npm lockfile v1/v3, requirements, Pipfile.lock, poetry.lock, uv.lock; runtime and dev; a package with no fix; traps: ranges, committed node_modules, vendored and yarn.lock as "outside") and `repo_secrets` (18 planted secrets in `rp-secrets-app`/`-infra`, fakes in `rp-secrets-traps`, `rp-clean`) |
| `st-*` | names in `dns/st.lab.test.db` whose subdomains point into stand-in provider zones (`dns/provider-*.db`), with the providers' web answers (`nginx/providers.conf`) and a crt.sh-format CT stand-in (`ct.lab.test`, `ct/`) | `subdomain_takeover`: 6 positives (S3 REST and website, Azure NXDOMAIN, Bitbucket, Surge, unlisted dangling) and 4 negatives (claimed resources, edge-case/unlisted providers with fingerprints, plain records, out-of-scope CT names) |

## Gate

`internal/accuracy/score.go`: precision >= 95%, recall >= 80%, at least 3 ground-truth findings,
at least one clean target, no check errors. The API refuses to enable a module whose check
does not meet it (`packages/shared/accuracy.json`).

## Repository targets (ADR-0006 §10)

- **Planted secrets are never committed.**
  - Files in `repos/` carry templates such as `{{secret:github_pat:app4}}`.
  - `labrepo` fills them from `internal/labfixture` (deterministic, seed-based, not real
    credentials) when it serves the tarball.
  - So GuardHub's own CI secret scan and GitHub's push protection stay meaningful.
  - `rp-secrets-traps` holds look-alikes only and is allowlisted by path in `.gitleaks.toml`.
- **OSV is replayed, not imitated.**
  - `osv/index.json` maps every `ecosystem|name|version` the lab asks to the advisory ids the
    real OSV API returned. `osv/vulns/<id>.json` are the records, byte for byte.
  - A query that was never recorded is an HTTP 500 and shows up as a lab error, never as
    "clean".
  - Re-record after changing a lockfile:
    `go run ./cmd/labrepo record --repos ../../test_corpus/repos --osv ../../test_corpus/osv`
    (from `apps/scanner`; asks the real api.osv.dev once).
- **Ground truth comes from independent tools**, on the materialized repositories
  (`go run ./cmd/labrepo materialize --repos … --out DIR`):
  - **Dependencies:** `ghcr.io/google/osv-scanner:v2.2.4 scan source -r DIR`. Its output is
    rated per docs/checks/dependency_vulns.md by a separate script using `packaging` (PEP 440)
    and `semver`: `rp-*.yaml` lists the key and the `fixed_version` (`params`) it gives.
    osv-scanner also reads `yarn.lock` and vendored directories; those are `outside: true`.
  - **Secrets:** each `rp-secrets-*` expectation names the planted secret, plus the gitleaks
    v8.21.2 rule that also finds it (14 of 18; the other 4 are formats gitleaks has no rule
    for).
- **Recorded on 2026-11-21.** The recording freezes the advisory data, so the measurement is
  stable. Re-recording (new advisories) means re-running osv-scanner and updating the
  manifests in the same change.
