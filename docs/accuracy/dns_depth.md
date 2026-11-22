# `dns_depth` accuracy

Lab source revision `c3afef35c824`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 100.0% | 20 | 0 | 0 | 0 | 0 | 80 | 60 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `caa_missing` | 1 | 0 | 0 |
| `dane_unsigned` | 1 | 0 | 0 |
| `dkim_key_too_short` | 1 | 0 | 0 |
| `dkim_weak_key` | 1 | 0 | 0 |
| `dnssec_broken` | 1 | 0 | 0 |
| `mta_sts_missing` | 11 | 0 | 0 |
| `mta_sts_mx_mismatch` | 1 | 0 | 0 |
| `mta_sts_policy_broken` | 1 | 0 | 0 |
| `mta_sts_testing` | 1 | 0 | 0 |
| `tlsrpt_missing` | 1 | 0 | 0 |

## False positives (0)

None.

## False negatives (0)

None.

## True positives (20)

- `dd-broken` / `dnssec_broken` at `DNSKEY broken.dd.lab.test`: DNS oracle (BIND dig/delv, OpenSSL, curl; test_corpus/oracles/dns, lab run 2026-11-23): delv broken.dd.lab.test (anchor = parent DS): ;; validating broken.dd.lab.test/DNSKEY: no valid signature found (DS)
- `dd-dkim1024` / `dkim_weak_key` at `TXT default._domainkey.dkim1024.dd.lab.test`: DNS oracle (BIND dig/delv, OpenSSL, curl; test_corpus/oracles/dns, lab run 2026-11-23): DKIM default._domainkey.dkim1024.dd.lab.test: RSA 1024 bits (OpenSSL)
- `dd-dkim512` / `dkim_key_too_short` at `TXT selector1._domainkey.dkim512.dd.lab.test`: DNS oracle (BIND dig/delv, OpenSSL, curl; test_corpus/oracles/dns, lab run 2026-11-23): DKIM default._domainkey.dkim512.dd.lab.test: RSA 2048 bits (OpenSSL); DKIM selector1._domainkey.dkim512.dd.lab.test: RSA 512 bits (OpenSSL)
- `dd-nocaa` / `caa_missing` at `CAA nocaa.dd.lab.test`: DNS oracle (BIND dig/delv, OpenSSL, curl; test_corpus/oracles/dns, lab run 2026-11-23): CAA: none at nocaa.dd.lab.test, dd.lab.test, lab.test
- `dd-nosts` / `mta_sts_missing` at `TXT _mta-sts.nosts.dd.lab.test`: DNS oracle (BIND dig/delv, OpenSSL, curl; test_corpus/oracles/dns, lab run 2026-11-23): MX: mx.nosts.dd.lab.test; _mta-sts: no single valid v=STSv1 record
- `dd-notlsrpt` / `tlsrpt_missing` at `TXT _smtp._tls.notlsrpt.dd.lab.test`: DNS oracle (BIND dig/delv, OpenSSL, curl; test_corpus/oracles/dns, lab run 2026-11-23): MX: mx.notlsrpt.dd.lab.test; curl https://mta-sts.notlsrpt.dd.lab.test/.well-known/mta-sts.txt: HTTP 200 text/plain dig TXT _smtp._tls: no v=TLSRPTv1 record.
- `dd-stsbroken` / `mta_sts_policy_broken` at `https://mta-sts.stsbroken.dd.lab.test/.well-known/mta-sts.txt`: DNS oracle (BIND dig/delv, OpenSSL, curl; test_corpus/oracles/dns, lab run 2026-11-23): curl https://mta-sts.stsbroken.dd.lab.test/.well-known/mta-sts.txt: HTTP 404 text/html
- `dd-stsmismatch` / `mta_sts_mx_mismatch` at `https://mta-sts.stsmismatch.dd.lab.test/.well-known/mta-sts.txt`: DNS oracle (BIND dig/delv, OpenSSL, curl; test_corpus/oracles/dns, lab run 2026-11-23): MX: mx.stsmismatch.dd.lab.test; curl https://mta-sts.stsmismatch.dd.lab.test/.well-known/mta-sts.txt: HTTP 200 text/plain Policy mx: mx.elsewhere.dd.lab.test only (dns/dd-sts/).
- `dd-ststesting` / `mta_sts_testing` at `https://mta-sts.ststesting.dd.lab.test/.well-known/mta-sts.txt`: DNS oracle (BIND dig/delv, OpenSSL, curl; test_corpus/oracles/dns, lab run 2026-11-23): curl https://mta-sts.ststesting.dd.lab.test/.well-known/mta-sts.txt: HTTP 200 text/plain Policy mode: testing (dns/dd-sts/).
- `dd-unsigned` / `dane_unsigned` at `TLSA _25._tcp.mx.unsigned.dd.lab.test`: DNS oracle (BIND dig/delv, OpenSSL, curl; test_corpus/oracles/dns, lab run 2026-11-23): TLSA at _25._tcp.mx.unsigned.dd.lab.test, zone unsigned.dd.lab.test has no DS
- `dns-axfr` / `mta_sts_missing` at `TXT _mta-sts.axfr.dns.lab.test`: DNS oracle (BIND dig/delv, OpenSSL, curl; test_corpus/oracles/dns, lab run 2026-11-23): MX: mx.axfr.dns.lab.test; _mta-sts: no single valid v=STSv1 record
- `dns-chunked` / `mta_sts_missing` at `TXT _mta-sts.chunked.dns.lab.test`: DNS oracle (BIND dig/delv, OpenSSL, curl; test_corpus/oracles/dns, lab run 2026-11-23): MX: mx.chunked.dns.lab.test; _mta-sts: no single valid v=STSv1 record
- `dns-good` / `mta_sts_missing` at `TXT _mta-sts.good.dns.lab.test`: DNS oracle (BIND dig/delv, OpenSSL, curl; test_corpus/oracles/dns, lab run 2026-11-23): MX: mx.good.dns.lab.test; _mta-sts: no single valid v=STSv1 record
- `dns-nodmarc` / `mta_sts_missing` at `TXT _mta-sts.nodmarc.dns.lab.test`: DNS oracle (BIND dig/delv, OpenSSL, curl; test_corpus/oracles/dns, lab run 2026-11-23): MX: mx.nodmarc.dns.lab.test; _mta-sts: no single valid v=STSv1 record
- `dns-nospf` / `mta_sts_missing` at `TXT _mta-sts.nospf.dns.lab.test`: DNS oracle (BIND dig/delv, OpenSSL, curl; test_corpus/oracles/dns, lab run 2026-11-23): MX: mx.nospf.dns.lab.test; _mta-sts: no single valid v=STSv1 record
- `dns-openres` / `mta_sts_missing` at `TXT _mta-sts.openres.dns.lab.test`: DNS oracle (BIND dig/delv, OpenSSL, curl; test_corpus/oracles/dns, lab run 2026-11-23): MX: mx.openres.dns.lab.test; _mta-sts: no single valid v=STSv1 record
- `dns-plusall` / `mta_sts_missing` at `TXT _mta-sts.plusall.dns.lab.test`: DNS oracle (BIND dig/delv, OpenSSL, curl; test_corpus/oracles/dns, lab run 2026-11-23): MX: mx.plusall.dns.lab.test; _mta-sts: no single valid v=STSv1 record
- `dns-pnone` / `mta_sts_missing` at `TXT _mta-sts.pnone.dns.lab.test`: DNS oracle (BIND dig/delv, OpenSSL, curl; test_corpus/oracles/dns, lab run 2026-11-23): MX: mx.pnone.dns.lab.test; _mta-sts: no single valid v=STSv1 record
- `dns-toomany` / `mta_sts_missing` at `TXT _mta-sts.toomany.dns.lab.test`: DNS oracle (BIND dig/delv, OpenSSL, curl; test_corpus/oracles/dns, lab run 2026-11-23): MX: mx.toomany.dns.lab.test; _mta-sts: no single valid v=STSv1 record
- `dns-twospf` / `mta_sts_missing` at `TXT _mta-sts.twospf.dns.lab.test`: DNS oracle (BIND dig/delv, OpenSSL, curl; test_corpus/oracles/dns, lab run 2026-11-23): MX: mx.twospf.dns.lab.test; _mta-sts: no single valid v=STSv1 record

