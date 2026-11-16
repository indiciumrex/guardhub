# ADR-0001 — Anonymous free scan still requires ownership proof

- **Status:** Accepted
- **Date:** 2026-11-16
- **Context sections:** GUARDHUB_STANDARDS.md §2.4, §8.7, §9.2

## Context

§8.7 asks for a free, one-time scan that does **not** require registration (viral hook).
§9.2 says **only targets whose ownership/access has been verified are scanned** and that this
section is non-negotiable. A naive "type any URL and we probe it" free scan would let anyone
point GuardHub at a third party's site — that violates §9.2 and §2.4.

## Decision

"No registration" ≠ "no permission". The anonymous scan flow is:

1. Visitor enters a URL → API issues a short-lived **verification challenge** (random token,
   24h expiry) bound to the target origin.
2. Visitor proves control of the origin with **one** of:
   - `https://<host>/.well-known/guardhub-verify.txt` containing the token,
   - `<meta name="guardhub-verification" content="<token>">` on the home page,
   - DNS TXT record `guardhub-verify=<token>` on `_guardhub.<host>` or `<host>`.
3. The **scanner** (the single hardened egress client) checks the proof. Only then is a scan
   queued. No account is needed; the visitor gets a one-time **scan access token** to view it.
4. After registering, the visitor can **claim** the scan; the verified challenge carries over
   as the project's ownership proof.

Abuse limits: anonymous challenges and scans are rate-limited per client IP and per target.

## Consequences

- Slightly more friction for the free scan, but GuardHub never probes a site the requester
  doesn't control. That's the product's credibility (§14 closing note).
- Verification checks are passive GETs/DNS lookups, so they follow the same do-no-harm rules as scans.
