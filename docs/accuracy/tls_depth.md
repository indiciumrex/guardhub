# `tls_depth` accuracy

Lab source revision `709c7f0ecbd3`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 100.0% | 5 | 0 | 0 | 0 | 0 | 110 | 105 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `cert_lifetime_too_long` | 1 | 0 | 0 |
| `cert_no_sct` | 1 | 0 | 0 |
| `cert_weak_signature` | 1 | 0 | 0 |
| `hsts_preload_ineligible` | 1 | 0 | 0 |
| `ocsp_stapling_missing` | 1 | 0 | 0 |

## False positives (0)

None.

## False negatives (0)

None.

## True positives (5)

- `td-longlife` / `cert_lifetime_too_long` at `td-longlife.lab.test:443`: testssl.sh 3.2 (drwetter/testssl.sh@sha256:64bab3c1…, --add-ca lab root, run 2026-11-22): cert_extlifeSpan '825 > 398 days' (MEDIUM).
- `td-nosct` / `cert_no_sct` at `td-nosct.lab.test:443`: testssl.sh 3.2 (drwetter/testssl.sh@sha256:64bab3c1…, --add-ca lab root, run 2026-11-22): certificate_transparency '--' (clean.lab.test: 'yes (certificate extension)').
- `td-ocspmiss` / `ocsp_stapling_missing` at `td-ocspmiss.lab.test:443`: testssl.sh 3.2 (drwetter/testssl.sh@sha256:64bab3c1…, --add-ca lab root, run 2026-11-22): cert_ocspURL 'http://ocsp.lab.test/', OCSP_stapling 'not offered' (LOW).
- `td-preload` / `hsts_preload_ineligible` at `https://td-preload.lab.test/`: testssl.sh 3.2 (drwetter/testssl.sh@sha256:64bab3c1…, --add-ca lab root, run 2026-11-22): HSTS_time 365 days, HSTS_subdomains 'only for this domain', HSTS_preload 'domain IS marked for preloading'; hstspreload.org requires includeSubDomains.
- `td-sha1` / `cert_weak_signature` at `td-sha1.lab.test:443`: testssl.sh 3.2 (drwetter/testssl.sh@sha256:64bab3c1…, --add-ca lab root, run 2026-11-22): cert_signatureAlgorithm 'ECDSA with SHA1' (MEDIUM).

