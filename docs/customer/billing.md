# Subscriptions and plan limits (Phase 5C): mechanism built, charging OFF

## What exists

- **Plans** `free`, `pro`, `agency` (`billing_plans`, migration 0027). Each has limits: websites,
  manual scans per day, scans at once, and the module tier (a module whose `min_plan` ranks above
  the account's plan is left out of its scans). Admins edit them in Admin → Billing (audited).
  All three are **seeded with today's behaviour** (25 sites, no practical scan cap), so nothing
  changes for any customer until the founder sets values. Only `free` is public.
- **Enforcement.**
  - Adding a website: the plan's site limit.
  - Manual scans: the daily limit and scans at once.
  - All scans, scheduled ones included: the module tier.
- **Trial.** Once per account, from free, only for a public plan with trial days. A daily job
  (00:15 UTC) ends expired trials and moves the account back to free. Audited as
  `billing.trial_started` and `billing.trial_ended`.
- **Manual assignment.** Admins assign a plan by e-mail with a reason, for customers billed
  outside the platform. Audited as `billing.plan_assigned`.
- **Guard.** `subscriptions` changes only in an admin or system context (DB trigger). A customer
  can never upgrade themselves.
- **Provider webhooks.** `POST /api/v1/billing/webhook/{provider}`:
  - It is exempt from the CSRF header (server-to-server) and authenticated by the provider's
    signature instead. Stripe's scheme is implemented, with a 5-minute window.
  - Each event is stored once per id (`billing_events`, body hash only).
  - `customer.subscription.*` events tagged with `metadata.guardhub_user_id` and
    `metadata.guardhub_plan` update the subscription.
  - While charging is off it answers `503 billing_not_live`.

## Taking money (the founder's gate)

Charging is live only when all of these are set **on the server** (never in the repository):

| Setting | Meaning |
|---|---|
| `BILLING_CHARGING_ENABLED=true` | the founder's switch |
| `BILLING_PROVIDER` | e.g. `stripe` (the first supported webhook format) |
| `BILLING_WEBHOOK_SECRET` | the provider's webhook signing secret |
| `BILLING_API_KEY` | the provider key, for checkout (only needed when checkout is added) |

Prices and the plan line-up are the founder's decision and live with the provider. The checkout
itself (sending a customer to pay) is deliberately not built yet:
- the API container has no internet route, and the provider's API would need to be added to the
  egress allow-list;
- until the founder decides, customers upgrade by contacting GuardHub and an admin assigns the
  plan.
