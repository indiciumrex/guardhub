# `cookie_depth` accuracy

Lab source revision `2f16aaca7c6a`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 100.0% | 5 | 0 | 0 | 0 | 0 | 104 | 99 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `cookie_domain_too_broad` | 2 | 0 | 0 |
| `cookie_prefix_invalid` | 3 | 0 | 0 |

## False positives (0)

None.

## False negatives (0)

None.

## True positives (5)

- `ck-domain` / `cookie_domain_too_broad` at `https://ck-domain.lab.test/#set-cookie=sid`: Header oracle (tough-cookie 5.1.2, lab run 2026-11-23): stored sid with domain=lab.test hostOnly=false (sent to every lab.test subdomain).
- `ck-domainself` / `cookie_domain_too_broad` at `https://ck-domainself.lab.test/#set-cookie=connect.sid`: Header oracle (tough-cookie 5.1.2, lab run 2026-11-23): stored connect.sid with domain=ck-domainself.lab.test hostOnly=false (sent to its subdomains too).
- `ck-hostdomain` / `cookie_prefix_invalid` at `https://ck-hostdomain.lab.test/#set-cookie=__Host-sid`: Header oracle (tough-cookie 5.1.2, lab run 2026-11-23): refused __Host-sid: Cookie has __Host prefix but either Secure or HostOnly attribute is not set or Path is not '/' (Domain attribute set).
- `ck-hostpath` / `cookie_prefix_invalid` at `https://ck-hostpath.lab.test/#set-cookie=__Host-sid`: Header oracle (tough-cookie 5.1.2, lab run 2026-11-23): refused __Host-sid: Cookie has __Host prefix but either Secure or HostOnly attribute is not set or Path is not '/' (Path=/app).
- `ck-secure` / `cookie_prefix_invalid` at `https://ck-secure.lab.test/#set-cookie=__Secure-sid`: Header oracle (tough-cookie 5.1.2, lab run 2026-11-23): refused __Secure-sid: Cookie has __Secure prefix but Secure attribute is not set.

