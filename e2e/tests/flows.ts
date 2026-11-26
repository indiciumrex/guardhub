/** Browser helpers shared by every journey (real UI, real API, the demo target only). */
import { expect, type Locator, type Page, type Response } from "@playwright/test";
import { DEMO_RAW_SECRET, nextTotpWindow, totp } from "./support";

export const PASSWORD = "e2e-Correct-Horse-Battery-9";

/** Records every scan status the browser itself received while polling. */
export function recordScanStatuses(page: Page): string[] {
  const seen: string[] = [];
  page.on("response", async (res: Response) => {
    if (!/\/api\/v1\/(public\/)?scans\/[0-9a-f-]+(\?|$)/.test(res.url()) || !res.ok()) return;
    try {
      const body = (await res.json()) as { status: string; progress: { status: string }[] };
      seen.push(body.status, ...body.progress.map((p) => `check:${p.status}`));
    } catch {
      // navigation raced the body; ignore
    }
  });
  return seen;
}

/** The finished demo-target report: plain-language findings and a masked secret (§9.1). */
export async function expectFinishedReport(page: Page) {
  await expect(page.getByText("Scan complete")).toBeVisible({ timeout: 150_000 });
  await expect(
    page.getByRole("heading", { name: "Security report for demo-target:8080" }),
  ).toBeVisible();
  const evidence = page.locator("details").filter({ hasText: "STRIPE_SECRET_KEY" }).first();
  await evidence.getByText("Show evidence (masked)").click();
  await expect(evidence.getByText(/STRIPE_SECRET_KEY=\*\*\*\*1234/)).toBeVisible();
  expect(await page.content()).not.toContain(DEMO_RAW_SECRET);
}

/**
 * Fills a controlled input once the page has hydrated. Typing earlier is lost when React
 * hydrates (the value is reset), so first wait for the page's scripts to finish loading.
 */
export async function fill(input: Locator, value: string) {
  await input.page().waitForLoadState("networkidle");
  await expect(async () => {
    await input.fill(value);
    await expect(input).toHaveValue(value, { timeout: 1_000 });
  }).toPass({ timeout: 20_000 });
}

export async function readField(page: Page, label: string): Promise<string> {
  const value = await page.getByLabel(label, { exact: true }).first().inputValue();
  expect(value).not.toBe("");
  return value;
}

/** Registers on the current /account/register page and completes the mandatory 2FA setup. */
export async function registerWith2fa(page: Page, address: string): Promise<string> {
  const email = page.getByLabel("Email address");
  const password = page.getByLabel("Password", { exact: true });
  // A late re-render can clear a field that was already filled and checked (seen in CI: the
  // e-mail field empty at submit, so the browser blocked the form and nothing happened). Retry
  // the whole form until the 2FA step is reached; a submit that went through is never repeated.
  await expect(async () => {
    if (/\/account\/2fa/.test(page.url())) return;
    await fill(email, address);
    await fill(password, PASSWORD);
    await expect(email).toHaveValue(address, { timeout: 1_000 });
    await page.getByRole("button", { name: "Create account" }).click();
    await page.waitForURL(/\/account\/2fa/, { timeout: 15_000 });
  }).toPass({ timeout: 60_000 });
  await expect(page.getByRole("img", { name: /QR code/ })).toBeVisible();
  const secret = (await page.locator("code").first().innerText()).trim();
  expect(secret).toMatch(/^[A-Z2-7]{16,}$/);
  await fill(page.getByLabel("6-digit code"), totp(secret));
  await page.getByRole("button", { name: "Verify" }).click();
  // first setup: the ten single-use recovery codes are shown once before going on
  const codes = page.getByRole("list", { name: "Your recovery codes" });
  await expect(codes.getByRole("listitem")).toHaveCount(10);
  await expect(codes.getByRole("listitem").first()).toHaveText(/^[a-z2-9]{5}-[a-z2-9]{5}$/);
  await page.getByRole("button", { name: "I saved them, continue" }).click();
  return secret;
}

/** Log in with password + TOTP (a fresh 30 s step, since codes can't be replayed). */
export async function signIn(page: Page, address: string, totpSecret: string) {
  expect(totpSecret, "the account must be registered first").not.toBe("");
  await page.goto("/account/login");
  await fill(page.getByLabel("Email address"), address);
  await fill(page.getByLabel("Password", { exact: true }), PASSWORD);
  await page.getByRole("button", { name: "Log in" }).click();
  await page.waitForURL(/\/account\/2fa/);
  await nextTotpWindow();
  await fill(page.getByLabel("6-digit code"), totp(totpSecret));
  await page.getByRole("button", { name: "Verify" }).click();
  await page.waitForURL(
    (url) => url.pathname.startsWith("/account") && !url.pathname.includes("2fa"),
  );
  await expect(page.getByText(`Signed in as ${address}`)).toBeVisible();
}

/** Registers a fresh account in its own browser context and returns it signed in. */
export async function newSignedInUser(
  page: Page,
  prefix: string,
): Promise<{ email: string; secret: string }> {
  const email = `${prefix}-${Date.now()}@example.com`;
  await page.goto("/account/register");
  const secret = await registerWith2fa(page, email);
  await page.waitForURL(
    (url) => url.pathname.startsWith("/account") && !url.pathname.includes("2fa"),
  );
  return { email, secret };
}
