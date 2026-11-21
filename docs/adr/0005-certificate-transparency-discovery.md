# ADR-0005 — Subdomain discovery asks a public Certificate Transparency search service

- **Status:** accepted
- **Date:** 2026-11-21
- **Context sections:** GUARDHUB_STANDARDS.md §2.4, §9.2, §9.3; ADR-0004

## Context

`subdomain_takeover` has to know a verified host's subdomains before it can check them. The Phase 2
prompt names the sources: Certificate Transparency (CT) logs plus DNS, with no aggressive brute
force.

- **CT logs** are public and append-only. Every publicly trusted certificate is in them, so they
  list most names a site has ever served over HTTPS, including those of services since deleted.
  Those are exactly the names that dangle.
- **Reading the logs directly** means downloading and indexing billions of entries. A search
  service (crt.sh, run by Sectigo) answers one query.

The question for the standards: §9.2 says target data does not leave GuardHub ("Hedefin verisi
dışarı çıkarılmaz"), and §9.3 says to collect the least data. Querying crt.sh sends the
**verified domain name** to a third party.

## Decision

1. **The check asks the crt.sh JSON API once per scan** with `q=%.<verified host>`. That query
   carries only the domain name, which is already public in the CT logs it searches. No finding,
   evidence, account or user data is sent. The request goes through the probe client, like every
   other probe (GET only, fixed User-Agent, budget, rate limit, IP guard).
2. **The endpoint is configurable:** `SCANNER_CT_URL`.
   - Empty means `https://crt.sh/`.
   - `off` disables CT; discovery then uses DNS only (the host plus ten fixed names).
   - The validation lab points it at its own stand-in (`ct.lab.test`), so the lab never reaches
     the internet.
3. **CT results are filtered before use:** only `<host>` and `*.<host>` are kept (§9.2). Names of
   other domains that share a certificate are discarded unread and never queried.
4. **A failing CT service never fails the check.** Discovery falls back to DNS.
5. The module ships **disabled** like every Phase 2 module. Enabling it in the admin is the
   founder's decision, and the privacy text names the CT lookup (see Consequences).

## Consequences

- crt.sh (Sectigo) learns which domains GuardHub scans, and when. It does not learn who asked,
  what was found or anything about the customer.
- crt.sh is often slow or overloaded. The 10 s probe timeout, bounded retries and the DNS fallback
  keep a scan from hanging on it, but on a bad day fewer names are checked. The finding set is
  then smaller, never wrong.
- **Founder decision (2026-11-21):** crt.sh stays on (`SCANNER_CT_URL` empty). The privacy text
  on the landing page (`landing.promise.privacy.body` in `ui.json`, en + tr) now names it: GuardHub
  searches the public CT logs (crt.sh) to find the verified domain's subdomains; only the domain
  name, already public in those logs, is sent, and no other data is shared. GuardHub has no
  separate privacy-policy page yet; when one is written, it must carry this disclosure.

## Alternatives considered

- **Brute-force wordlists** (what the replaced engine did: 143k names, about 287k queries, no
  rate limit). Rejected: aggressive, and §9.2 says passive and rate-limited.
- **Running our own CT log index.** Correct but heavy: storage, ingestion and operations. It is a
  possible later step if the crt.sh dependency becomes a problem.
- **Paid CT APIs** (Cert Spotter, Censys). They have the same disclosure property, plus an API key
  to manage. Possible later behind the same `SCANNER_CT_URL` seam, which today speaks crt.sh's
  format.
