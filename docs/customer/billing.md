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
| `BILLING_API_KEY` | the provider's secret API key, used by the checkout |
| `BILLING_PRICE_IDS` | `pro=price_...,agency=price_...`: the provider price for each paid plan |
| `BILLING_EGRESS_PROXY` | the CONNECT egress proxy the API reaches the provider through |

Prices and the plan line-up are the founder's decision and live with the provider: no price is
in the repository or shown by GuardHub; the provider's page shows it.

## The checkout (built, inert)

- `POST /api/v1/billing/checkout {plan}` answers `409 billing_not_live` unless charging is live,
  the provider is `stripe`, the API key is set and the plan has a price in `BILLING_PRICE_IDS`.
  The plan must be public and above the customer's current plan (`422 plan_not_available`).
- When it is live, the API creates a Stripe Checkout Session (subscription mode, one line item,
  `subscription_data.metadata.guardhub_user_id` / `guardhub_plan`, the signed-in e-mail), and
  returns only Stripe's URL. The browser follows it only if it is `https://checkout.stripe.com/…`.
- The plan changes only when the signed webhook `customer.subscription.*` arrives; the return
  page (`/account/plan?checkout=done|cancelled`) never changes anything by itself.
- `/account/plan/checkout?plan=…` shows the plan's limits and, while charging is off, only
  "Payments are not switched on" with no button. The plan page links to it only for the plans in
  `checkout_plans` (empty while off).

### Switching it on (the founder, on the server)

1. Create the products and prices in the provider; set `BILLING_PRICE_IDS`.
2. Set `BILLING_PROVIDER=stripe`, `BILLING_API_KEY`, `BILLING_WEBHOOK_SECRET` (webhook URL
   `https://guardhub.dev/api/v1/billing/webhook/stripe`, events `customer.subscription.*`).
3. Add `api.stripe.com` to the egress proxy allow-list and set `BILLING_EGRESS_PROXY`.
4. Make the paid plans public (Admin → Billing), set `BILLING_CHARGING_ENABLED=true`, recreate
   the serving colour's api and re-run gates A–K.

Until then customers upgrade by contacting GuardHub and an admin assigns the plan.
