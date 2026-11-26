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
  const meRow = page.getByRole("row", { name: new RegExp(email.replace(/[.+]/g, "\\$&")) });
  await expect(meRow).toBeVisible();
  await expect(meRow.getByRole("button", { name: /^Disable/ })).toHaveCount(0); // never yourself
  await expect(page.getByRole("region", { name: "Security policy" })).toContainText(
    "Two-factor sign-in is required for every account",
  );
  // an admin invitation: the link is shown once, then it can be revoked
  const inviteForm = page.getByRole("form", { name: "Invite an admin" });
  await inviteForm.getByLabel("E-mail address").fill("e2e-new-admin@example.com");
  await inviteForm.getByRole("button", { name: "Create invitation" }).click();
  await expect(page.getByLabel("Invitation link")).toContainText(
    "/account/admin-invite?token=ghi_",
  );
  await page.getByRole("button", { name: "Done" }).click();
  await shoot(page, "admin-users");
  await page
    .getByRole("button", { name: "Revoke the invitation for e2e-new-admin@example.com" })
    .click();
  await expect(
    page.getByRole("row", { name: /e2e-new-admin@example\.com/ }).getByText("Revoked"),
  ).toBeVisible();
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

  // configuration: the security controls are listed as not editable, secrets never show, and a
  // bounded change is recorded in the history and reverted from there
  await nav.getByRole("link", { name: "Configuration" }).click();
  await expect(page.getByRole("heading", { name: "Configuration", level: 1 })).toBeVisible();
  await expect(page.getByRole("region", { name: "Safety status" })).toBeVisible();
  const fixed = page.getByRole("region", { name: "Not editable here" });
  await expect(fixed).toContainText("The four active-testing locks");
  await expect(fixed).toContainText("Ownership proof (§9.2)");
  await expect(page.getByRole("rowheader", { name: "jwt_secret" })).toBeVisible();
  await expect(
    page.getByRole("row", { name: /jwt_secret/ }).getByText("Secret configured"),
  ).toBeVisible();
  const limit = page.getByLabel("Manual re-scans per project");
  await limit.fill("8");
  const changed = page.waitForResponse(
    (r) => r.url().includes("/admin/config/settings/rate.rescan_per_project_hour") && r.ok(),
  );
  await page
    .getByRole("listitem")
    .filter({ has: limit })
    .getByRole("button", { name: "Save" })
    .click();
  await changed;
  const history = page.getByRole("region", { name: "Change history" });
  await expect(history.getByRole("row", { name: /rate\.rescan_per_project_hour/ })).toContainText(
    "default → 8",
  );
  await shoot(page, "admin-config");
  const reverted = page.waitForResponse((r) => r.url().includes("/revert") && r.ok());
  await history
    .getByRole("row", { name: /rate\.rescan_per_project_hour/ })
    .first()
    .getByRole("button", { name: "Revert" })
    .click();
  await reverted;
  await expect(history.getByRole("row", { name: /Reverted/ }).first()).toContainText("8 → default");

  // alerts: four rules, a threshold change that persists, and a mute that shows until undone
  await nav.getByRole("link", { name: "Alerts" }).click();
  await expect(page.getByRole("heading", { name: "Alerts", level: 1 })).toBeVisible();
  await expect(page.getByRole("region", { name: "Open alerts" })).toBeVisible();
  const rules = page.getByRole("region", { name: "Rules" });
  await expect(rules.getByRole("form")).toHaveCount(4);
  const apiRule = rules.getByRole("form", { name: "API errors (5xx)" });
  await apiRule.getByLabel("Alert at (errors)").fill("25");
  const ruleSaved = page.waitForResponse(
    (r) => r.url().endsWith("/admin/alerts/rules/api_errors") && r.ok(),
  );
  await apiRule.getByRole("button", { name: "Save rule" }).click();
  await ruleSaved;
  await page.reload();
  await expect(
    rules.getByRole("form", { name: "API errors (5xx)" }).getByLabel("Alert at (errors)"),
  ).toHaveValue("25");
  const muted = page.waitForResponse((r) => r.url().endsWith("/api_errors/mute") && r.ok());
  await rules
    .getByRole("form", { name: "API errors (5xx)" })
    .getByRole("button", { name: "1 hour" })
    .click();
  await muted;
  await expect(rules.getByText(/Muted until/)).toBeVisible();
  await shoot(page, "admin-alerts");
  const unmuted = page.waitForResponse((r) => r.url().endsWith("/api_errors/mute") && r.ok());
  await rules
    .getByRole("form", { name: "API errors (5xx)" })
    .getByRole("button", { name: "Unmute" })
    .click();
  await unmuted;
  await expect(rules.getByText(/Muted until/)).toHaveCount(0);

  // reports: customers are masked on screen and in the CSV export
  await nav.getByRole("link", { name: "Reports" }).click();
  await expect(page.getByRole("heading", { name: "Reports", level: 1 })).toBeVisible();
  await page.getByRole("link", { name: "Customers" }).click();
  const report = page.getByRole("region", { name: /Customers · 30 days/ });
  await expect(report.getByText("Masked", { exact: true })).toBeVisible();
  await expect(report.getByRole("cell", { name: /\*\*\*@/ }).first()).toBeVisible();
  await expect(report.getByRole("cell", { name: /@example\.com$/ })).toHaveCount(0);
  const csvHref = await report.getByRole("link", { name: "Download CSV" }).getAttribute("href");
  expect(csvHref).toBe("/api/v1/admin/reports/customers?days=30&format=csv");
  const csv = await page.request.get(csvHref!);
  expect(csv.ok()).toBe(true);
  expect(csv.headers()["content-type"]).toContain("text/csv");
  expect(await csv.text()).not.toMatch(/[a-z0-9-]+@example\.com/);
  await shoot(page, "admin-reports");

  // integrations: a key is shown once, works on the integration API only, and can be revoked
  await nav.getByRole("link", { name: "API & integrations" }).click();
  await expect(page.getByRole("heading", { name: "API & integrations", level: 1 })).toBeVisible();
  await expect(page.getByRole("region", { name: "What a key can never do" })).toBeVisible();
  const createForm = page.getByRole("form", { name: "Create an API key" });
  await createForm.getByLabel("Name").fill("e2e pipeline");
  await createForm.getByLabel("Read projects").check();
  await createForm.getByRole("button", { name: "Create key" }).click();
  const secretBox = page.getByLabel("New API key");
  await expect(secretBox).toHaveText(/^ghk_/);
  const apiKey = (await secretBox.textContent()) ?? "";
  const asKey = await page.request.get("/api/v1/integrations/projects", {
    headers: { Authorization: `Bearer ${apiKey}` },
  });
  expect(asKey.status()).toBe(200);
  await page.getByRole("button", { name: "Done" }).click();
  await expect(page.getByText(apiKey)).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Endpoint traffic" })).toBeVisible();
  await shoot(page, "admin-integrations");
  const revoked = page.waitForResponse((r) => r.url().endsWith("/revoke") && r.ok());
  await page.getByRole("button", { name: "Revoke key e2e pipeline" }).click();
  await revoked;
  await expect(page.getByRole("row", { name: /e2e pipeline/ }).getByText("Revoked")).toBeVisible();
  const afterRevoke = await page.request.get("/api/v1/integrations/projects", {
    headers: { Authorization: `Bearer ${apiKey}` },
  });
  expect(afterRevoke.status()).toBe(401);

  // webhooks: an unsafe address is refused; a public one is added with a one-time secret.
  // The .invalid name never resolves, so nothing leaves the test network.
  const hookForm = page.getByRole("form", { name: "Add a webhook" });
  await hookForm.getByLabel("Name").fill("e2e hook");
  await hookForm.getByLabel("Address").fill("https://10.0.0.5/in");
  await hookForm.getByRole("button", { name: "Add webhook" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "public https://" })).toBeVisible();
  await hookForm.getByLabel("Address").fill("https://hooks.guardhub-e2e.invalid/in");
  await hookForm.getByRole("button", { name: "Add webhook" }).click();
  await expect(page.getByLabel("Signing secret")).toHaveText(/^whsec_/);
  await page.getByRole("button", { name: "Done" }).click();
  await page.getByRole("button", { name: "Switch off webhook e2e hook" }).click();
  await expect(page.getByRole("button", { name: "Switch on webhook e2e hook" })).toBeVisible();

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
