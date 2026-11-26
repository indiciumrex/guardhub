# Customer panel (Phase 5A)

`/account`, separate from the admin console. Every page shows the signed-in customer's own data
only: the API enforces it with row-level security, the web never filters.

The flow: sign up (two-factor required), add a website, prove ownership (§9.2: a file, a meta
tag or DNS), passive scan, then findings and risk, report and alerts. A site is never scanned
before its ownership proof.

- **Overview.**
  - The "Getting started" steps (account, site, verify, scan, review, alerts). They are computed
    from the customer's data in `lib/onboarding.ts` and lead to the next step.
  - The risk summary: websites, verified, critical and high findings open in each site's latest
    scan, the lowest score.
  - The sites table: ownership, last scan, score, critical/high, next scheduled scan.
  - Adding a website, and the GitHub app.
- **Alerts.** E-mail and Slack settings, a test message and the history (unchanged).
- **Security.**
  - Two-factor status and recovery codes (shown once; new ones need a current code).
  - The customer's own sessions, with "sign out" for one or everywhere: `GET /auth/sessions`
    and `POST /auth/sessions/end`. Only the account's own sessions; another account's session
    id does nothing. Audited as `auth.sessions_ended`.
- **Reports.** The scan report page (plain language, fixes, evidence) and the scan comparison and
  score trend, as before.

Active tests on customer sites are not part of this: see Phase 5B (built, off).
