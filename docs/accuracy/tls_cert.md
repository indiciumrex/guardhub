# `tls_cert` accuracy

Lab source revision `a38ed80ac882+wip`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 100.0% | 15 | 0 | 0 | 0 | 0 | 21 | 6 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `cert_expired` | 1 | 0 | 0 |
| `cert_hostname_mismatch` | 1 | 0 | 0 |
| `cert_untrusted` | 2 | 0 | 0 |
| `http_not_redirected` | 1 | 0 | 0 |
| `https_unavailable` | 9 | 0 | 0 |
| `legacy_tls_supported` | 1 | 0 | 0 |

## False positives (0)

None.

## False negatives (0)

None.

## True positives (15)

- `drupal` / `https_unavailable` at `drupal.lab.test:443`: Nothing listens on 443.
- `dvwa` / `https_unavailable` at `dvwa.lab.test:443`: Nothing listens on 443.
- `grafana` / `https_unavailable` at `grafana.lab.test:443`: Nothing listens on 443.
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

