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

## Targets

| Target | What it is | Main use |
|---|---|---|
| `clean` | nginx, hardened (TLS 1.2+, full chain, strict headers, flagged cookie) | false positives: must find nothing |
| `tls-*` | `clean`, wrong in exactly one TLS property each | `tls_cert` |
| `leaky` | a careless static deployment (.env, .git, .aws, autoindex) | `exposed_env`, `info_leak` |
| `juice-shop` | OWASP Juice Shop (SPA: 200 for every path) | soft-404 trap, `info_leak`, `open_admin` |
| `dvwa` | DVWA + MariaDB | headers, versions, cookies |
| `webgoat` | OWASP WebGoat (empty 404 at `/`) | non-document trap |
| `phpmyadmin`, `grafana`, `wordpress`, `drupal` | real products in default setups | `open_admin`, `default_creds` |
| `st-*` | names in `dns/st.lab.test.db` whose subdomains point into stand-in provider zones (`dns/provider-*.db`), with the providers' web answers (`nginx/providers.conf`) and a crt.sh-format CT stand-in (`ct.lab.test`, `ct/`) | `subdomain_takeover`: 6 positives (S3 REST and website, Azure NXDOMAIN, Bitbucket, Surge, unlisted dangling) and 4 negatives (claimed resources, edge-case/unlisted providers with fingerprints, plain records, out-of-scope CT names) |

## Gate

`internal/accuracy/score.go`: precision >= 95%, recall >= 80%, at least 3 ground-truth findings,
at least one clean target, no check errors. The API refuses to enable a module whose check
does not meet it (`packages/shared/accuracy.json`).
