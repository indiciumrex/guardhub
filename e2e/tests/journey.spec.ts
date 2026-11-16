/**
 * Launch gate B: the whole product, through the real UI, in a real browser.
 *
 *   anonymous scan (prove ownership → live progress → plain report, secrets masked)
 *   → "save this scan" → register → mandatory 2FA → claimed into a project → history → rescan
 *   → add a second project → verify ownership → scan
 *   → log out → log in with 2FA
 *   → non-admin gets 404 on /admin → operator promotes via CLI → admin panel works
 *   → report renders in Turkish
 *   → negative paths: internal address refused, unverified target never scanned.
 */
import { expect, test, type Locator, type Page, type Response } from "@playwright/test";
import {
  composeExec,
  DEMO_RAW_SECRET,
  DEMO_TARGET,
  nextTotpWindow,
  publishOwnershipToken,
  removeOwnershipToken,
  resetLocalRateLimits,
  totp,
} from "./support";

test.describe.configure({ mode: "serial" });

const email = `e2e-${Date.now()}@example.com`;
const password = "e2e-Correct-Horse-Battery-9";
let totpSecret = "";

test.beforeAll(() => {
  if (process.env.E2E_LOCAL_STACK !== "0") resetLocalRateLimits();
  removeOwnershipToken();
});
test.afterAll(() => removeOwnershipToken());

/** Records every scan status the browser itself received while polling. */
function recordScanStatuses(page: Page): string[] {
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

async function expectFinishedReport(page: Page) {
  await expect(page.getByText("Scan complete")).toBeVisible({ timeout: 150_000 });
  await expect(
    page.getByRole("heading", { name: "Security report for demo-target:8080" }),
  ).toBeVisible();
  // the exposed .env is reported, and its secret is masked (§9.1)
  const evidence = page.locator("details").filter({ hasText: "STRIPE_SECRET_KEY" }).first();
  await evidence.getByText("Show evidence (masked)").click();
  await expect(evidence.getByText(/STRIPE_SECRET_KEY=\*\*\*\*1234/)).toBeVisible();
  expect(await page.content()).not.toContain(DEMO_RAW_SECRET);
}

/**
 * Fills a controlled input once the page has hydrated. Typing earlier is lost when React
 * hydrates (the value is reset), so first wait for the page's scripts to finish loading.
 */
async function fill(input: Locator, value: string) {
  await input.page().waitForLoadState("networkidle");
  await expect(async () => {
    await input.fill(value);
    await expect(input).toHaveValue(value, { timeout: 1_000 });
  }).toPass({ timeout: 20_000 });
}

async function readField(page: Page, label: string): Promise<string> {
  const value = await page.getByLabel(label, { exact: true }).first().inputValue();
  expect(value).not.toBe("");
  return value;
}

test("anonymous scan: ownership proof, live progress, plain report, save → register → 2FA → claim", async ({
  page,
}) => {
  const statuses = recordScanStatuses(page);

  await page.goto("/scan");
  await fill(page.getByLabel("Your website address"), DEMO_TARGET);
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByRole("heading", { name: /Prove that you control/ })).toBeVisible();

  // without the proof, the scan is refused and nothing is queued
  await page.getByRole("button", { name: "Verify & start scan" }).click();
  await expect(
    page.getByText("We couldn't confirm that you control this website yet."),
  ).toBeVisible({
    timeout: 60_000,
  });
  expect(statuses).toEqual([]);

  publishOwnershipToken(await readField(page, "File content (verification code)"));
  await page.getByRole("button", { name: "Verify & start scan" }).click();
  await page.waitForURL(/\/scan\/[0-9a-f-]+$/);

  await expectFinishedReport(page);
  // the browser saw the scan in flight before it finished (live progress, §8.2)
  expect(statuses.some((s) => s === "queued" || s === "running")).toBe(true);
  expect(statuses).toContain("check:done");

  // save it: the account area requires login → register → mandatory 2FA
  await page.getByRole("button", { name: "Save this scan & rescan later" }).click();
  await page.waitForURL(/\/account\/login/);
  await page.getByRole("link", { name: "Create an account" }).click();
  totpSecret = await registerWith2fa(page, email);

  // claimed into a project that is already verified (ownership was proven for the scan)
  await page.waitForURL(/\/account\/projects\/[0-9a-f-]+$/, { timeout: 30_000 });
  await expect(page.getByText(/Ownership verified on/)).toBeVisible();
  const history = page.getByRole("table", { name: /Previous scans/ });
  await expect(history.getByRole("row")).toHaveCount(2); // header + the claimed scan

  // rescan from the history page
  await page.getByRole("button", { name: "Rescan" }).click();
  await page.waitForURL(/\/account\/scans\/[0-9a-f-]+$/);
  await expectFinishedReport(page);
  await page.getByRole("link", { name: "← Back to project" }).click();
  await expect(history.getByRole("row")).toHaveCount(3);
});

test("account: duplicate refused; a second user adds, verifies and scans their own project", async ({
  page,
  browser,
}) => {
  await signIn(page);
  await page.goto("/account");
  await fill(page.getByLabel("Project name"), "Same site again");
  await fill(page.getByLabel("Website address"), DEMO_TARGET);
  await page.getByRole("button", { name: "Add project" }).click();
  await expect(page.getByText("You already have a project for this address.")).toBeVisible();

  // a different person: sees none of the first user's projects (RLS), adds the site themselves
  const context = await browser.newContext();
  const other = await context.newPage();
  await other.goto("/account/register");
  await registerWith2fa(other, `e2e-b-${Date.now()}@example.com`);
  await other.waitForURL((url) => url.pathname === "/account");
  await expect(other.getByText("You don't have any projects yet.")).toBeVisible();

  await fill(other.getByLabel("Project name"), "Demo site (direct)");
  await fill(other.getByLabel("Website address"), DEMO_TARGET);
  await other.getByRole("button", { name: "Add project" }).click();
  await other.waitForURL(/\/account\/projects\/[0-9a-f-]+$/);

  const rescan = other.getByRole("button", { name: "Rescan" });
  await expect(rescan).toBeDisabled(); // no scanning before ownership is proven
  removeOwnershipToken();
  await other.getByRole("button", { name: "Verify", exact: true }).click();
  await expect(
    other.getByText("We couldn't confirm that you control this website yet."),
  ).toBeVisible({ timeout: 60_000 });
  await expect(rescan).toBeDisabled();

  publishOwnershipToken(await readField(other, "File content (verification code)"));
  await other.getByRole("button", { name: "Verify", exact: true }).click();
  await expect(other.getByText(/Ownership verified on/)).toBeVisible({ timeout: 60_000 });

  await rescan.click();
  await other.waitForURL(/\/account\/scans\/[0-9a-f-]+$/);
  await expectFinishedReport(other);
  await other.getByRole("link", { name: "← Back to project" }).click();
  await expect(other.getByRole("table", { name: /Previous scans/ }).getByRole("row")).toHaveCount(
    2,
  );
  await context.close();
});

test("admin: hidden (404) for a normal user, first admin promoted by the operator CLI", async ({
  page,
  browser,
}) => {
  const anonymous = await browser.newContext();
  const anon = await anonymous.newPage();
  expect((await anon.goto("/admin"))?.status()).toBe(404);
  await anonymous.close();

  await signIn(page);
  expect((await page.goto("/admin"))?.status()).toBe(404);
  await expect(page.getByRole("heading", { name: "We couldn't find that page" })).toBeVisible();

  const out = composeExec("api", [
    "python",
    "-m",
    "guardhub_api.admin.bootstrap",
    "promote",
    email,
  ]);
  expect(out).toContain("is now 'admin'");

  expect((await page.goto("/admin"))?.status()).toBe(200);
  await expect(page.getByRole("heading", { name: "Administration" })).toBeVisible();
  await expect(page.getByRole("cell", { name: email })).toBeVisible();
  await expect(
    page.getByText("Not configured. The core product runs fully without AI."),
  ).toBeVisible();

  // toggle a module off and back on (both are audited server-side); the switch is optimistic,
  // so each step waits for the API to confirm before checking the persisted state
  const toggle = () => page.getByRole("switch", { name: "Enable Information leaks" });
  const flip = async () => {
    const saved = page.waitForResponse(
      (r) =>
        r.url().includes("/api/v1/admin/modules/info_leak") && r.request().method() === "PATCH",
    );
    await toggle().click();
    expect((await saved).status()).toBe(200);
  };
  await expect(toggle()).toHaveAttribute("aria-checked", "true");
  await flip();
  await page.reload();
  await expect(toggle()).toHaveAttribute("aria-checked", "false");
  await flip();
  await page.reload();
  await expect(toggle()).toHaveAttribute("aria-checked", "true");
});

test("report is shown in Turkish after switching language", async ({ page }) => {
  await signIn(page);
  await page.goto("/account");
  await page.getByRole("link", { name: "demo-target:8080", exact: true }).click();
  await page
    .getByRole("link", { name: /View report/ })
    .first()
    .click();
  await expectFinishedReport(page);

  await page
    .getByRole("button", { name: /Language|English/ })
    .first()
    .click();
  await page.getByRole("option", { name: "Türkçe" }).click();
  await expect(
    page.getByRole("heading", { name: "demo-target:8080 için güvenlik raporu" }),
  ).toBeVisible();
  await expect(page.getByText("Tarama tamamlandı")).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("lang", "tr");
  await expect(page.getByRole("contentinfo").getByText("HKSolutions").first()).toBeVisible(); // brand, §8.1
});

test("refuses internal addresses and never scans an unverified target", async ({ page }) => {
  const queued: string[] = [];
  page.on("request", (r) => {
    if (/\/public\/challenges\/[^/]+\/scan$/.test(r.url())) queued.push(r.url());
  });
  await page.goto("/scan");
  for (const internal of ["http://redis:6379", "http://localhost", "http://169.254.169.254"]) {
    await fill(page.getByLabel("Your website address"), internal);
    await page.getByRole("button", { name: "Continue" }).click();
    await expect(page.getByRole("alert").filter({ hasText: "Error" })).toContainText(
      "That doesn't look like a public website address we can scan.",
    );
    await expect(page.getByRole("heading", { name: /Prove that you control/ })).toHaveCount(0);
  }
  expect(queued).toEqual([]);
});

/** Log in with password + TOTP (a fresh 30 s step, since codes can't be replayed). */
async function signIn(page: Page) {
  expect(totpSecret, "the first journey registers the account").not.toBe("");
  await page.goto("/account/login");
  await fill(page.getByLabel("Email address"), email);
  await fill(page.getByLabel("Password", { exact: true }), password);
  await page.getByRole("button", { name: "Log in" }).click();
  await page.waitForURL(/\/account\/2fa/);
  await nextTotpWindow();
  await fill(page.getByLabel("6-digit code"), totp(totpSecret));
  await page.getByRole("button", { name: "Verify" }).click();
  await page.waitForURL(
    (url) => url.pathname.startsWith("/account") && !url.pathname.includes("2fa"),
  );
  await expect(page.getByText(`Signed in as ${email}`)).toBeVisible();
}

/** Registers on the current /account/register page and completes the mandatory 2FA setup. */
async function registerWith2fa(page: Page, address: string): Promise<string> {
  await fill(page.getByLabel("Email address"), address);
  await fill(page.getByLabel("Password", { exact: true }), password);
  await page.getByRole("button", { name: "Create account" }).click();

  await page.waitForURL(/\/account\/2fa/);
  await expect(page.getByRole("img", { name: /QR code/ })).toBeVisible();
  const secret = (await page.locator("code").first().innerText()).trim();
  expect(secret).toMatch(/^[A-Z2-7]{16,}$/);
  await fill(page.getByLabel("6-digit code"), totp(secret));
  await page.getByRole("button", { name: "Verify" }).click();
  return secret;
}
