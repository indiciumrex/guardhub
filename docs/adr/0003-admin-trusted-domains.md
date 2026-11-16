# ADR-0003: Admin trusted domains (prove once, scan without the prompt)

- Status: accepted
- Date: 2026-11-17
- Touches: GUARDHUB_STANDARDS §9.2 (scan only targets whose ownership is verified), §2.4

## Context

Admins (the founding team) scan GuardHub's own and partner sites often. Proving ownership on
every new project or re-verification is friction. The request was "scan without ownership
friction". Scanning **any** URL without proof would break §9.2 and is rejected outright, for
admins too.

## Decision

1. An admin adds a host to their **trusted domains** and proves ownership **once** with the usual
   methods (well-known file, meta tag, DNS TXT) via the scanner's verify job.
2. While the domain is `active`, that admin can create projects for that **exact host** (scheme
   and port taken from the verified origin; subdomains are NOT included) and scan them without
   any proof prompt. Those projects are stored with `ownership_method = 'trusted_domain'`.
3. Trust is not forever: the proof must **stay published**. A background job (Arq, daily)
   silently re-runs the verification. If the proof is gone, the domain becomes `suspended`
   (audited); its projects then behave like any project whose verification lapsed: the next
   scan requires a fresh proof. Re-verifying the domain reactivates it.
4. Only the `admin` role (re-checked from the database on every request) can use the list; RLS
   additionally restricts rows to the owning admin.
5. Every add, verify, suspend, reactivate and remove is written to the append-only AuditLog.
6. Hosts that were never proven still require the normal ownership proof. There is no
   "scan without proof" path anywhere in the code.

## Consequences

- §9.2 still holds: every scanned target has a proof that is currently published; the only
  change is *when* the admin is asked for it (once), not *whether* it exists.
- Domain transfers are covered by the background re-check (bounded by the re-check interval).
- Exact-host matching avoids a verified apex silently covering third-party subdomains.
