# `tls_cert` accuracy

Lab source revision `69ee5204062c+wip`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 100.0% | 38 | 0 | 0 | 0 | 0 | 44 | 6 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `cert_expired` | 1 | 0 | 0 |
| `cert_hostname_mismatch` | 1 | 0 | 0 |
| `cert_untrusted` | 2 | 0 | 0 |
| `http_not_redirected` | 1 | 0 | 0 |
| `https_unavailable` | 32 | 0 | 0 |
| `legacy_tls_supported` | 1 | 0 | 0 |

## False positives (0)

None.

## False negatives (0)

None.

## True positives (38)

- `dns-axfr` / `https_unavailable` at `axfr.dns.lab.test:443`: Plain HTTP only (dns-web): nothing listens on 443.
- `dns-chunked` / `https_unavailable` at `chunked.dns.lab.test:443`: Plain HTTP only (dns-web): nothing listens on 443.
- `dns-dkimonly` / `https_unavailable` at `dkimonly.dns.lab.test:443`: Plain HTTP only (dns-web): nothing listens on 443.
- `dns-dkimreject` / `https_unavailable` at `dkimreject.dns.lab.test:443`: Plain HTTP only (dns-web): nothing listens on 443.
- `dns-good` / `https_unavailable` at `good.dns.lab.test:443`: Plain HTTP only (dns-web): nothing listens on 443.
- `dns-nodmarc` / `https_unavailable` at `nodmarc.dns.lab.test:443`: Plain HTTP only (dns-web): nothing listens on 443.
- `dns-nomail` / `https_unavailable` at `nomail.dns.lab.test:443`: Plain HTTP only (dns-web): nothing listens on 443.
- `dns-nospf` / `https_unavailable` at `nospf.dns.lab.test:443`: Plain HTTP only (dns-web): nothing listens on 443.
- `dns-nullmx` / `https_unavailable` at `nullmx.dns.lab.test:443`: Plain HTTP only (dns-web): nothing listens on 443.
- `dns-openres` / `https_unavailable` at `openres.dns.lab.test:443`: Plain HTTP only (dns-web): nothing listens on 443.
- `dns-plusall` / `https_unavailable` at `plusall.dns.lab.test:443`: Plain HTTP only (dns-web): nothing listens on 443.
- `dns-pnone` / `https_unavailable` at `pnone.dns.lab.test:443`: Plain HTTP only (dns-web): nothing listens on 443.
- `dns-toomany` / `https_unavailable` at `toomany.dns.lab.test:443`: Plain HTTP only (dns-web): nothing listens on 443.
- `dns-twospf` / `https_unavailable` at `twospf.dns.lab.test:443`: Plain HTTP only (dns-web): nothing listens on 443.
- `drupal` / `https_unavailable` at `drupal.lab.test:443`: Nothing listens on 443.
- `dvwa` / `https_unavailable` at `dvwa.lab.test:443`: Nothing listens on 443.
- `grafana` / `https_unavailable` at `grafana.lab.test:443`: Nothing listens on 443.
- `hh-cors-cred` / `https_unavailable` at `hh-cors-cred.lab.test:443`: Plain HTTP only: nothing listens on 443.
- `hh-cors-null` / `https_unavailable` at `hh-cors-null.lab.test:443`: Plain HTTP only: nothing listens on 443.
- `hh-cors-public` / `https_unavailable` at `hh-cors-public.lab.test:443`: Plain HTTP only: nothing listens on 443.
- `hh-csp-strict` / `https_unavailable` at `hh-csp-strict.lab.test:443`: Plain HTTP only: nothing listens on 443.
- `hh-csp-weak` / `https_unavailable` at `hh-csp-weak.lab.test:443`: Plain HTTP only: nothing listens on 443.
- `hh-csrf-cookie` / `https_unavailable` at `hh-csrf-cookie.lab.test:443`: Plain HTTP only: nothing listens on 443.
- `hh-meta-csp` / `https_unavailable` at `hh-meta-csp.lab.test:443`: Plain HTTP only: nothing listens on 443.
- `hh-referrer` / `https_unavailable` at `hh-referrer.lab.test:443`: Plain HTTP only: nothing listens on 443.
- `hh-xfo-allowfrom` / `https_unavailable` at `hh-xfo-allowfrom.lab.test:443`: Plain HTTP only: nothing listens on 443.
- `juice-shop` / `https_unavailable` at `juice-shop.lab.test:443`: Nothing listens on 443: the app is served over plain HTTP only.
- `leaky` / `https_unavailable` at `leaky.lab.test:443`: Nothing listens on 443.
- `phpmyadmin` / `https_unavailable` at `phpmyadmin.lab.test:443`: Nothing listens on 443.
- `tls-expired` / `cert_expired` at `tls-expired.lab.test:443`: labpki 'expired': notAfter is 30 days in the past (chain otherwise valid).
- `tls-httponly` / `https_unavailable` at `tls-httponly.lab.test:443`: Nothing listens on 443.
- `tls-legacy` / `legacy_tls_supported` at `tls-legacy.lab.test:443`: nginx ssl_protocols includes TLSv1 (SECLEVEL=0).
- `tls-nochain` / `cert_untrusted` at `tls-nochain.lab.test:443`: labpki 'nochain': the intermediate is not served, so the chain cannot be built to the root.
- `tls-noredirect` / `http_not_redirected` at `http://tls-noredirect.lab.test/`: Port 80 serves the page (200) instead of redirecting to HTTPS.
- `tls-selfsigned` / `cert_untrusted` at `tls-selfsigned.lab.test:443`: labpki 'selfsigned': the leaf is self-signed, not under the lab root.
- `tls-wronghost` / `cert_hostname_mismatch` at `tls-wronghost.lab.test:443`: labpki 'wronghost': the certificate names only other.lab.test.
- `webgoat` / `https_unavailable` at `webgoat.lab.test:443`: Nothing listens on 443.
- `wordpress` / `https_unavailable` at `wordpress.lab.test:443`: Nothing listens on 443.

