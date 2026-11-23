# `dns_email` accuracy

Lab source revision `2f16aaca7c6a`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 100.0% | 9 | 0 | 0 | 0 | 0 | 104 | 95 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `dmarc_missing` | 1 | 0 | 0 |
| `dmarc_not_enforced` | 2 | 0 | 0 |
| `open_resolver` | 1 | 0 | 0 |
| `spf_allow_all` | 1 | 0 | 0 |
| `spf_invalid` | 2 | 0 | 0 |
| `spf_missing` | 1 | 0 | 0 |
| `zone_transfer_open` | 1 | 0 | 0 |

## False positives (0)

None.

## False negatives (0)

None.

## True positives (9)

- `dns-axfr` / `zone_transfer_open` at `AXFR axfr.dns.lab.test @ns.dns.lab.test`: dig AXFR axfr.dns.lab.test @ns.dns.lab.test: 7 records; other zones: Transfer failed.
- `dns-dkimonly` / `dmarc_not_enforced` at `TXT _dmarc.dkimonly.dns.lab.test`: dig: _dmarc.dkimonly.dns.lab.test is 'v=DMARC1; p=none;'; the domain sends mail via DKIM (resend._domainkey).
- `dns-nodmarc` / `dmarc_missing` at `TXT _dmarc.nodmarc.dns.lab.test`: dig: _dmarc.nodmarc.dns.lab.test has no TXT; _dmarc.lab.test is NXDOMAIN.
- `dns-nospf` / `spf_missing` at `TXT nospf.dns.lab.test`: dig: MX 10 mx.nospf..., no TXT starting with v=spf1.
- `dns-openres` / `open_resolver` at `NS ns-open.dns.lab.test`: dig A clean.lab.test @ns-open: NOERROR, RA set, 1 answer; @ns (the other nameserver): REFUSED.
- `dns-plusall` / `spf_allow_all` at `TXT plusall.dns.lab.test`: dig: the SPF record ends in +all: every sender passes SPF (and so DMARC alignment).
- `dns-pnone` / `dmarc_not_enforced` at `TXT _dmarc.pnone.dns.lab.test`: dig: _dmarc.pnone.dns.lab.test is 'v=DMARC1; p=none; ...'.
- `dns-toomany` / `spf_invalid` at `TXT toomany.dns.lab.test`: dig: include:n0.mailer -> n1 -> ... -> n11: 12 includes.
- `dns-twospf` / `spf_invalid` at `TXT twospf.dns.lab.test`: dig: two TXT records start with v=spf1.

