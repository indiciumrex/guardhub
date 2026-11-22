# Check `dns_email` — e-mail spoofing protection and DNS

- **Code:** `apps/scanner/internal/checks/dns_email.go`, `spf.go` (+ `internal/probe/dns.go`) · tests: `dns_email_test.go`, `spf_test.go`
- **Category:** dns · **i18n:** `checks.json` → `dns_email` · **Module:** ships disabled (migration 0006); enabling requires the accuracy gate
- **Accuracy:** [`docs/accuracy/dns_email.md`](../accuracy/dns_email.md) · **Decision record:** [ADR-0004](../adr/0004-phase2-reimplementation-and-accuracy-gate.md)

## What it detects

| Finding key | Severity | Params | Trigger |
|---|---|---|---|
| `spf_allow_all` | high | `domain` | the effective SPF `all` is `+all` or a bare `all`: every sender passes SPF, and so DMARC alignment |
| `spf_invalid` | medium | `domain`, `reason` | permanent SPF error: several `v=spf1` records, more than 10 DNS lookups (followed recursively, RFC 7208 §4.6.4), a syntax error, an include/redirect to a domain without SPF, or a loop |
| `spf_missing` | medium | `domain` | the domain has MX records (receives mail) but no `v=spf1` record |
| `dmarc_missing` | medium | `domain` | a mail domain (MX, or an SPF that allows senders) with no valid DMARC at `_dmarc.<host>` nor at the organisational domain (RFC 7489 §6.6.3) |
| `dmarc_not_enforced` | low | `domain` | the applicable DMARC policy is `p=none` (or `sp=none` from the organisational domain) |
| `open_resolver` | medium | `nameserver` | a nameserver of the zone answers a recursive question about another domain (RA set and an answer) |
| `zone_transfer_open` | medium | `nameserver` | AXFR of the zone is answered, starting with the zone's SOA |

## Scope and do-no-harm

- **Record lookups go through the recursive resolver** (the container's system resolver, or
  `SCANNER_DNS_SERVER`). This is the same public data any mail server reads.
- **Nameservers are only contacted when the verified host is the apex of its own DNS zone**
  (the SOA belongs to the host). The contact is one recursive-question query and one AXFR request
  per nameserver (at most 4). Each reads one message and closes the connection, and no zone data
  is stored.
- **The owner of `shop.example.com` has not proven control of `example.com`**, so that zone's
  nameservers are never asked anything (`TestDNSEmailNeverTouchesParentZoneNameservers`). This
  follows §9.2.
- Every query counts against the scan's request budget. Nameserver connections go through the
  probe client's IP guard.

## Decisions against false positives

- **A lookup error is never "missing".** SERVFAIL, a timeout or REFUSED skips that rule. If no
  lookup is answered at all, the check reports an error, not findings.
- **A domain counts as a mail domain** when it has MX records, an SPF record that allows
  senders, **or a DMARC record on the host itself**. The last case is today's e-mail-provider
  pattern (Resend, SendGrid, Postmark, SES with a custom MAIL FROM): the From domain carries only
  DKIM and DMARC, while MX and SPF sit on `send.<domain>`. A pre-release run against our own
  domain found exactly this. guardhub.dev sends through Resend with DMARC `p=none`, and the first
  version of the rule missed it. The lab now has this pattern twice (`p=none` positive,
  `p=reject` negative).
- **No mail findings for domains that handle no mail:**
  - a null MX (RFC 7505);
  - no MX and no SPF;
  - `v=spf1 -all` with no MX: no DMARC finding, because the domain says it sends nothing.
- **TXT records made of several strings are joined without a separator** (RFC 7208 §3.3; long
  DKIM/SPF records are split at 255 bytes). The lab has an SPF record split mid-token: joining
  with a space would make it look invalid.
- **SPF parsing follows RFC 7208:**
  - only `v=spf1` exactly (not `v=spf10`) starts a record;
  - `redirect=` applies only without `all`;
  - an include's `all` does not decide the outer result;
  - macros are not expanded (they need a sender);
  - unknown modifiers are allowed.
- **DMARC:** several records mean "no policy", `p` is required, and `sp=` applies to subdomains.

## Deliberately not reported

- **Missing DKIM.** Its absence cannot be proven without the selector, which only real e-mails
  reveal. Guessing about 75 selectors (as the engine this replaces did) marks almost every domain
  "DKIM missing". DMARC enforcement is what turns DKIM into protection, and that is reported.
- **DNSSEC.** "Unsigned" is true of most domains and is not an actionable risk for a SaaS
  founder. A broken chain (signed, but failing validation) is reported by `dns_depth`
  ([docs/checks/dns_depth.md](dns_depth.md)), a separate module with its own accuracy gate.
- **CAA, MTA-STS, TLS-RPT, DANE, DKIM key size:** in `dns_depth` too, never here (ADR-0007 §1:
  depth ships as a new module, not as new keys of this enabled one).

## Evidence

Kind `dns_record`. The location is the record or exchange (`TXT host`, `TXT _dmarc.host`,
`NS ns`, `AXFR host @ns`). The payload holds the SPF record and its problem, the MX hosts, the
DMARC location, or the counts of what a nameserver answered (never zone contents). All of it is
public DNS data.
