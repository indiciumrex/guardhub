# Check `dns_depth` — DNSSEC, CAA and e-mail transport beyond SPF/DMARC

- **Code:** `apps/scanner/internal/checks/dns_depth.go` · tests: `dns_depth_test.go`
- **i18n:** `checks.json` → `dns_depth` (en, tr; the other locales are in the translation queue, §7.5)
- **Module:** ships disabled (migration 0010)
- **Accuracy:** [`docs/accuracy/dns_depth.md`](../accuracy/dns_depth.md) · **Decision record:** [ADR-0007](../adr/0007-phase4a-depth-methodology.md)

## What it detects

| Finding key | Severity | Params | When |
|---|---|---|---|
| `dnssec_broken` | medium | `domain`, `reason` | the parent publishes DS records for the zone holding the host, but no DNSKEY matches them (`ds_mismatch`, `no_dnskey`), or no DS-matched key validly signs the DNSKEY set (`signature_expired`, `dnskey_not_signed`) |
| `caa_missing` | info | `domain` | no CAA record at the host or any parent up to the registrable domain (RFC 8659 tree climb) |
| `mta_sts_missing` | low | `domain` | the host receives mail (MX, not null MX) and has no single valid `v=STSv1` record at `_mta-sts` (RFC 8461 §3.1) |
| `mta_sts_policy_broken` | low | `domain`, `reason` | the record exists, but the policy cannot be used as senders require: no HTTPS or an invalid certificate for `mta-sts.<host>` (`https_unreachable`, `certificate_invalid`), not HTTP 200 (`http_status`), not `text/plain` (`content_type`) or not a valid policy (`policy_invalid`) |
| `mta_sts_mx_mismatch` | medium | `domain`, `mx` | the policy is in `enforce` mode and an MX host is not covered by any of its `mx` patterns |
| `mta_sts_testing` | info | `domain` | a valid policy in `testing` mode |
| `tlsrpt_missing` | info | `domain` | MTA-STS is published but there is no `v=TLSRPTv1` record at `_smtp._tls` (RFC 8460) |
| `dane_unsigned` | info | `mx` | an MX host (first 4) publishes TLSA records at `_25._tcp.<mx>`, but its zone has no DS record, so senders ignore them (RFC 7672) |
| `dkim_weak_key` | low | `selector`, `bits` | an RSA DKIM key of 1024–2047 bits under one of the probed selectors |
| `dkim_key_too_short` | medium | `selector`, `bits` | an RSA DKIM key under 1024 bits under one of the probed selectors |

**Severity (ADR-0007 rubric):**

- **medium**:
  - Broken DNSSEC makes the domain unresolvable for validating resolvers (Google, Cloudflare,
    Quad9, many ISPs): the same class as "major browsers refuse the site".
  - An enforced MTA-STS policy that misses an MX host makes compliant senders refuse delivery.
  - A DKIM key under 1024 bits can be factored at modest cost. Forged signatures pass only at
    receivers that still accept such keys, which RFC 8301 forbids, hence medium rather than high.
- **low**:
  - Missing or unusable MTA-STS: the downgrade attack needs an attacker on the path between
    mail servers.
  - A 1024-bit DKIM key: accepted everywhere, below the 2048-bit recommendation.
- **info**: CAA, MTA-STS testing mode, TLS-RPT and unsigned DANE are defence in depth and
  reporting. None is a direct risk.

## How it works

All DNS lookups go through the scan's recursive resolver (request budget, rate limit). DNSSEC
data is read with the **CD bit**, so a validating resolver still returns the records of a broken
zone, and the break itself can be examined.

1. **Zone of the host:** the SOA owner (answer, or the authority section of a NODATA/NXDOMAIN).
   An alias (CNAME) lives in its parent's zone.
2. **DNSSEC:**
   - DS at the parent, then the DNSKEY set with its RRSIGs.
   - Each DS digest is recomputed from the keys.
   - The DNSKEY set's signature is verified with a DS-matched key at the scan's clock.
   - Algorithms 5, 7, 8, 10, 13, 14 and 15 and digests 1, 2 and 4 are checked; other DS
     records are left out.
3. **CAA:** one lookup per name from the host up to its registrable domain (Public Suffix
   List).
4. **Mail transport, only for a host with MX records (not null MX):**
   - `_mta-sts` TXT.
   - If it is present, **one TLS handshake with `mta-sts.<host>`** (certificate verified
     against the system roots for that name) and **one GET** of
     `/.well-known/mta-sts.txt` with no redirects. This is the file every sending mail server
     fetches, on a subdomain of the verified host.
   - Then `_smtp._tls` TXT.
   - TLSA at `_25._tcp.<mx>` for the first 4 MX hosts, and DS for an MX host's zone when TLSA
     is present.
5. **DKIM:** TXT at `<selector>._domainkey.<host>` for a fixed list of widely used selectors:
   `default`, `dkim`, `google`, `k1`, `k2`, `mail`, `resend`, `s1`, `s2`, `selector1`,
   `selector2`, `smtp`. Only RSA keys (`k=rsa`, the default) are sized, from the modulus, in
   SubjectPublicKeyInfo or PKCS#1 form. The same key published under several selectors is
   reported once.

Nothing is ever sent to the domain's mail servers. Cost: about 25 DNS lookups, plus 2 HTTPS
requests when an MTA-STS record exists.

## Not reported (false-positive discipline)

- **A lookup failure is never "missing".** SERVFAIL or a timeout stops the rule it belongs to.
  If every lookup fails, the check reports an error instead of a clean result.
- **Unsigned zones.** "No DNSSEC" is true of most domains and is not actionable (see
  `dns_email`); only a broken chain is reported. A resolver that strips signatures makes the
  signature test unjudgeable, so it is skipped. The DS-digest test does not need signatures.
- **Missing DKIM.** It is unprovable without the real selector. A key found under a probed
  selector is a fact; a key not found proves nothing.
- **MTA-STS mode `none`.** This is an explicit opt-out, not a broken policy.
- **DANE not used.** Only TLSA records that senders must ignore are reported. The TLSA data is
  not compared with the mail server's certificate (that would need an SMTP connection).
- **No duplicate of `dns_email`.** SPF, DMARC, open resolvers and zone transfers stay there.

## Validation

**Lab targets** (`dd-*`, zones in `test_corpus/dns/dd/`):

- Each `<name>.dd.lab.test` is its own zone, delegated from `dd.lab.test`.
- `labdns` signs it at lab start with throwaway keys (CoreDNS `dnssec` plugin) and writes the
  matching DS into the parent. For `broken`, the DS is that of another key.
- MTA-STS policies are served over HTTPS with lab certificates by `dd-sts`
  (`nginx/dd-sts.conf`, `dns/dd-sts/`).
- `dd-good`, `dd-www` (a name inside a covered zone) and `dd-nomail` are the negatives. Every
  other target is `dd-good` with one difference.

**Independent truth:**

- `test_corpus/oracles/dns` runs BIND's `delv` (DNSSEC validation with the parent's DS as the
  only trust anchor), `dig`, OpenSSL (DKIM key size) and curl (the MTA-STS fetch with the lab
  CA and no redirects).
- It applies the RFC rules to their output and compares the result with every manifest. CI's
  `dns-truth` job runs it and fails on any disagreement.
- The `dns-*` mail domains carry `mta_sts_missing` from the same oracle: they have MX records
  and no `_mta-sts` record.
- Lab names served by Docker's resolver (not in a lab zone) answer SERVFAIL for most types, so
  neither the oracle nor the check can derive anything there. The oracle lists them as
  "no DNS data".

**In the lab, `lab.test` answers a definite "no CAA"** (template in `Corefile.res`), so the CAA
climb of a `dd` target ends there. The existing `dns.lab.test` and `st.lab.test` zones carry a
CAA record at their apex: their targets are not about CAA.
