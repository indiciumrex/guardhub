/**
 * Phase 1 / ADR-0003: admin trusted domains, through the real UI.
 *   non-admin → 404 · admin proves the demo site ONCE → "Scan now" with no proof prompt
 *   → the proof is withdrawn but trust holds (re-checked daily, not per scan)
 *   → a different port of the same host still needs its own proof (exact origin only)
 *   → removing the trusted domain makes the next rescan refuse instead of scanning.
 */
import { expect, test } from "@playwright/test";
import { expectFinishedReport, fill, newSignedInUser, readField } from "./flows";
import {
  composeExec,
  DEMO_TARGET,
  publishOwnershipToken,
  removeOwnershipToken,
  resetLocalRateLimits,
} from "./support";

test.describe.configure({ mode: "serial" });

test.beforeAll(() => {
  if (process.env.E2E_LOCAL_STACK !== "0") resetLocalRateLimits();
  removeOwnershipToken();
});
test.afterAll(() => removeOwnershipToken());

test("trusted domains: hidden from non-admins, prove once, scan without a prompt, exact origin only", async ({
  page,
  browser,
}) => {
  // a normal user doesn't even learn the page exists
  const other = await browser.newContext();
  const otherPage = await other.newPage();
  await newSignedInUser(otherPage, "e2e-td-user");
  expect((await otherPage.goto("/admin/trusted-domains"))?.status()).toBe(404);
  await other.close();

  const admin = await newSignedInUser(page, "e2e-td-admin");
  expect(
    composeExec("api", ["python", "-m", "guardhub_api.admin.bootstrap", "promote", admin.email]),
  ).toContain("is now 'admin'");

  await page.goto("/admin");
  await page
    .getByRole("navigation", { name: "Administration sections" })
    .getByRole("link", { name: "Trusted domains" })
    .click();
  await expect(page.getByRole("heading", { name: "Trusted domains", level: 1 })).toBeVisible();
  await fill(page.getByLabel("Website address"), DEMO_TARGET);
  await page.getByRole("button", { name: "Add domain" }).click();
  await expect(page.getByText("Pending").first()).toBeVisible();

  // verifying without the proof published keeps it pending
  removeOwnershipToken();
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect(
    page.getByText("We couldn't confirm that you control this website yet."),
  ).toBeVisible({ timeout: 60_000 });
  await expect(page.getByText("Active")).toHaveCount(0);

  publishOwnershipToken(await readField(page, "File content (verification code)"));
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect(page.getByText("Active").first()).toBeVisible({ timeout: 60_000 });

  // the proof is withdrawn: trust holds until the daily re-check, so the scan needs no prompt
  removeOwnershipToken();
  await page.getByRole("button", { name: "Scan now" }).click();
  await page.waitForURL(/\/account\/scans\/[0-9a-f-]+$/);
  await expectFinishedReport(page);

  // the project created for it is verified through the trusted domain
  await page.getByRole("link", { name: "← Back to project" }).click();
  await expect(page.getByText(/Ownership verified/)).toBeVisible();
  const projectUrl = page.url();

  // exact origin only: the same host on another port still needs its own proof
  await page.goto("/account");
  await fill(page.getByLabel("Project name"), "Same host, other port");
  await fill(page.getByLabel("Website address"), "http://demo-target:8081");
  await page.getByRole("button", { name: "Add project" }).click();
  await page.waitForURL(/\/account\/projects\/[0-9a-f-]+$/);
  await expect(page.getByRole("button", { name: "Rescan" })).toBeDisabled();
  await expect(page.getByText("File content (verification code)").first()).toBeVisible();

  // removing the trusted domain: the next rescan refuses instead of scanning
  await page.goto("/admin/trusted-domains");
  await page.getByRole("button", { name: "Remove" }).first().click();
  await page.getByRole("button", { name: "Yes, remove it" }).click();
  await expect(page.getByText("You haven't added any trusted domains yet.")).toBeVisible();

  await page.goto(projectUrl);
  const queued: string[] = [];
  page.on("response", (r) => {
    if (/\/projects\/[0-9a-f-]+\/scans$/.test(r.url()) && r.request().method() === "POST") {
      queued.push(String(r.status()));
    }
  });
  await page.getByRole("button", { name: "Rescan" }).click();
  await expect(
    page.getByText(/The trusted domain for this site isn't active right now/),
  ).toBeVisible();
  expect(queued).toEqual(["422"]);
});
