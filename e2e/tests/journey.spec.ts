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
import { expect, test, type Page } from "@playwright/test";
import {
  expectFinishedReport,
  fill,
  readField,
  recordScanStatuses,
  registerWith2fa,
  signIn as signInAs,
} from "./flows";
import {
  composeExec,
  DEMO_TARGET,
  publishOwnershipToken,
  removeOwnershipToken,
  resetLocalRateLimits,
} from "./support";

test.describe.configure({ mode: "serial" });

const email = `e2e-${Date.now()}@example.com`;
let totpSecret = "";

test.beforeAll(() => {
  if (process.env.E2E_LOCAL_STACK !== "0") resetLocalRateLimits();
  removeOwnershipToken();
});
test.afterAll(() => removeOwnershipToken());

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
  await expect(
    page.getByText("Not configured. The core product runs fully without AI."),
  ).toBeVisible();
  // the safety status leads the console: every active-testing lock is shown, all locked
  const safety = page.getByRole("region", { name: "Safety status" });
  await expect(safety).toBeVisible();
  await expect(safety.getByText("Active testing OFF")).toBeVisible();
  await expect(safety.getByText("Locked: awaiting founder approval")).toBeVisible();
  await expect(safety.getByText("Gate M (active checks)")).toBeVisible();
  await expect(page.getByText("Powered by").first()).toBeVisible(); // brand in the console, §8.1
  await shoot(page, "admin-overview");
  // the control centre's sections: users, then the Module Center
  const nav = page.getByRole("navigation", { name: "Administration sections" });
  await nav.getByRole("link", { name: "Users" }).click();
  await expect(page.getByRole("cell", { name: email })).toBeVisible();
  await nav.getByRole("link", { name: "Module Center" }).click();
  await expect(page.getByRole("heading", { name: "Module Center", level: 1 })).toBeVisible();
  // the gate rule is visible: active tests are locked with the reason, not switchable
  await expect(page.getByText("No gate, no ON")).toBeVisible();
  await shoot(page, "admin-modules");
  // scan orchestration (active testing reported off), findings & risk, audit & monitoring
  await nav.getByRole("link", { name: "Scans" }).click();
  await expect(page.getByRole("heading", { name: "Scan orchestration", level: 1 })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Active testing (Phase 4B)" })).toBeVisible();
  // owner-target active scan: the locks are listed and the form cannot start (nothing is on)
  await expect(page.getByText("Blocked by:")).toBeVisible();
  await expect(page.getByRole("button", { name: "Start the active scan" })).toBeDisabled();
  await shoot(page, "admin-scans");
  await nav.getByRole("link", { name: "Findings & risk" }).click();
  await expect(page.getByRole("heading", { name: "Findings & risk", level: 1 })).toBeVisible();
  await shoot(page, "admin-findings");
  await nav.getByRole("link", { name: "Audit & monitoring" }).click();
  await expect(page.getByRole("heading", { name: "Audit log" })).toBeVisible();
  await expect(page.getByRole("columnheader", { name: "IP (hash)" })).toBeVisible();
  await shoot(page, "admin-audit");
  await nav.getByRole("link", { name: "Module Center" }).click();

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

const signIn = (page: Page) => signInAs(page, email, totpSecret);

/** Full-page screenshots of the admin console in light and dark (CI artifact admin-screenshots). */
async function shoot(page: Page, name: string): Promise<void> {
  for (const colorScheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme });
    await page.screenshot({ path: `screenshots/${name}-${colorScheme}.png`, fullPage: true });
  }
  await page.emulateMedia({ colorScheme: "light" });
}
