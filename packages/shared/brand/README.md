# GuardHub brand assets

Single source for the GuardHub brand (GUARDHUB_STANDARDS §8.1). GuardHub is a product of
**HKSolutions**. Every public touch point (landing, scan screen, reports, account, admin, trust
page, emails, invoices, error pages) shows the GuardHub logo and the line
"Powered by HKSolutions" (localised in the UI as `brand.poweredBy`).

## Files

| File | Use |
|---|---|
| `logo.svg` | Full logo: shield mark + "GuardHub" wordmark. Use on light backgrounds. |
| `mark.svg` | Shield mark alone: favicons, app icons, tight spaces (min. 16 px). |

React versions live in `apps/web/components/brand/` (`Logo`, `ShieldMark`, `PoweredBy`). They
switch to the dark-mode colours automatically, so prefer them in the web app.

## The mark

A shield (protection) split into a navy face and a slightly lighter navy side (depth), with an
inner teal outline and a teal check mark: "we checked, and here's what's fine". It's geometric
and drawn in a 48 × 48 grid, with no gradients, so it stays crisp at 16 px.

## Colours

| Token | Hex | Use |
|---|---|---|
| Navy 900 | `#0B2545` | Primary brand colour, shield face, "Guard" in the wordmark, headings |
| Navy 800 | `#13315C` | Shield side, dark surfaces |
| Navy 950 | `#071833` | Dark-mode page background |
| Teal 700 | `#0F766E` | "Hub" in the wordmark, primary buttons and links on light backgrounds (AA on white) |
| Teal 400 | `#2DD4BF` | Check mark; accents and links on dark backgrounds |
| Slate 50 | `#F8FAFC` | Light-mode page background |

Severity colours are never the only signal: the UI always pairs them with a text label and icon.

## Typography

The system font stack (`ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, …`). We
don't fetch any external fonts, which keeps the CSP strict and pages fast. The wordmark is set
bold with a slight negative letter-spacing.

## Usage rules

- Keep clear space around the logo equal to the height of the check mark.
- Don't recolour, stretch, rotate, outline or add effects to the logo.
- On dark backgrounds, use the React components (dark variant) or set the wordmark in white
  with "Hub" in Teal 400.
- "Powered by HKSolutions" sits in the footer, in muted text, and is never removed.
