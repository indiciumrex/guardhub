# Check `subdomain_takeover` — subdomains that point at a deleted third-party resource

- **Code:** `apps/scanner/internal/checks/subdomain_takeover.go`, `takeover_providers.go`, provider data `takeover_providers.yaml` · tests: `subdomain_takeover_test.go`
- **Category:** dns · **i18n:** `checks.json` → `subdomain_takeover` · **Module:** ships disabled (migration 0007); enabling requires the accuracy gate
- **Accuracy:** [`docs/accuracy/subdomain_takeover.md`](../accuracy/subdomain_takeover.md) · **Decision records:** [ADR-0004](../adr/0004-phase2-reimplementation-and-accuracy-gate.md), [ADR-0005](../adr/0005-certificate-transparency-discovery.md)

## What it detects

| Finding key | Severity | Params | Trigger |
|---|---|---|---|
| `unclaimed_resource` | high | `subdomain`, `provider` | a hop of the name's CNAME chain points into a provider on the **curated list** **and** that provider's "not claimed" fingerprint is seen: its NXDOMAIN (asked twice) or its HTTP error answer for the name |
| `dangling_cname` | low | `subdomain`, `target` | the chain ends in NXDOMAIN (asked twice) at a name **outside the owner's registrable domain** that is not at a listed provider: broken, but no proven takeover path |

**Not a finding:**

- A CNAME into a provider whose resource answers normally. "A CNAME into S3 exists" is never
  reported on its own; that was the defect of the engine this replaces (ADR-0004).
- A provider that is not on the list, even when its page shows a listed provider's fingerprint
  text.
- A 2xx page that mentions the fingerprint text, such as a help article about "Repository not
  found".
- A name that no longer exists, with no CNAME.
- A CNAME to a missing name inside the owner's own registrable domain. Only the owner can create
  that name, so nobody else can take it over.
- Lookups that fail (SERVFAIL, timeout): "could not tell" never becomes "dangling".

## How it works (read-only)

1. **Discovery, in scope only.** Three sources:
   - the verified host itself;
   - the names CT logs have seen under it: one query to the crt.sh JSON API for `%.<host>`;
   - ten fixed names commonly pointed at hosted services: `www blog docs help support status shop
     cdn assets static`.

   This is not a brute force: at most ten guessed names, one DNS query each. Only `<host>` and
   names ending in `.<host>` are kept. crt.sh's search also returns other names that share a
   certificate (the parent, siblings, look-alikes such as `evil<host>`); they are dropped
   **before any query** (`TestSubdomainTakeoverStaysInScope`, lab target `st-scope`).

   The owner of `shop.example.com` has not proven `example.com` (§9.2). So scanning
   `shop.example.com` covers `*.shop.example.com`, never its siblings.
2. **Resolution.** The check asks the recursive resolver for A records, as a browser's resolver
   does, and reads the CNAME chain from the answer. If the answer stops at a target it did not
   follow, that target is asked next (at most 4 hops). qtype CNAME is not used because some
   resolvers (Docker's among them) refuse it.
3. **Decision.**
   - **NXDOMAIN at the end of the chain:**
     - confirmed by a second query;
     - a listed `nxdomain` provider (Azure, Elastic Beanstalk, Discourse) gives `unclaimed_resource`;
     - any other target outside the owner's registrable domain gives `dangling_cname`.
   - **Chain into a listed `http` provider:**
     - one GET of `http://<name>/`, then `https://` if http did not answer;
     - same-host redirects only, a GET with no body, the standard probe envelope;
     - a non-2xx answer containing the fingerprint gives `unclaimed_resource`.

**GuardHub never creates, registers or claims anything.** No account, no bucket, no API call to a
provider: the only traffic is DNS queries, one CT query and GETs to the customer's own subdomains.

## The curated provider list

`apps/scanner/internal/checks/takeover_providers.yaml` (embedded at build time). A provider is
listed only when all three hold:

1. [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) marks it status
   **Vulnerable**.
2. It has a CNAME pattern.
3. It has a fingerprint specific to the provider.

Reviewed 2026-11-21. On the list:

- **`nxdomain` kind:** Microsoft Azure (15 suffixes such as `azurewebsites.net`, `cloudapp.net`,
  `blob.core.windows.net`), AWS Elastic Beanstalk, Discourse.
- **`http` kind:** AWS S3 (REST and website endpoints, every region), Agile CRM, Bitbucket, Ghost,
  HatenaBlog, Help Juice, Help Scout, JetBrains YouTrack, Ngrok, Readme.io, Strikingly, Surge.sh,
  SurveySparrow, Uberflip, WordPress.com, Worksites.

**Deliberately not listed:**

- **Edge case** (claiming needs a verification step, or depends on account settings): GitHub
  Pages, Heroku, Netlify, Shopify, Tumblr, Webflow, Wix.
- **Not vulnerable:** Fastly, CloudFront, Unbounce and others.
- **Fingerprint too generic** to be safe: Gemfury (Next.js default 404), Anima (Rails default
  404), Uptimerobot ("page not found"), Cargo ("404 Not Found"), and Helprace and LaunchRock
  (status code only).

The loader refuses fingerprints shorter than 12 characters, providers without a CNAME pattern, and
unknown kinds (`TestTakeoverProvidersLoad`).

**To update:**

1. Re-read `fingerprints.json` and apply the three rules.
2. Add a lab target for any fingerprint you are unsure of.
3. Run `bash test_corpus/run.sh`.

## Cost and limits

- Per scan, at most:
  - 40 names;
  - 4 CNAME hops per name;
  - 10 fingerprint GETs;
  - 70 network operations in total, including the CT query.
- A domain with hundreds of CT names is checked only partly: the host first, then CT names in
  sorted order, then the fixed names. This is a stated limit of a bounded scan.
- Measured lab max: 16 operations (`docs/accuracy/`). The scan budget is 220, sized so this check's
  cap fits next to the others' maxima (docs/architecture.md).
- A slow or failing CT service is not an error: discovery falls back to DNS names.
  `SCANNER_CT_URL=off` turns CT off.

## False-positive and false-negative risks

- **False positives** would need all three of these:
  - a listed provider;
  - its fingerprint in an error answer for exactly that name;
  - a name in the verified host's scope.

  The lab's negatives cover:
  - claimed resources at listed providers (200 site, private S3 bucket, live Beanstalk name);
  - edge-case and unlisted providers that show fingerprints;
  - a 2xx page mentioning a fingerprint;
  - out-of-scope CT names that are themselves dangling.
- **False negatives:**
  - names not in CT and not among the ten fixed names;
  - providers not on the list;
  - a provider that answered **2xx** for an unclaimed name (the conservative 2xx rule would miss
    it);
  - more than 40 names.

## Evidence

- **Kind `http_response`** (location = the URL fetched): the CNAME chain, the status code and
  which fingerprint matched. No page content is stored.
- **Kind `dns_record`** (location = `CNAME <name>`): the chain and the NXDOMAIN fact.

All of it is public DNS data or the provider's generic error page.
