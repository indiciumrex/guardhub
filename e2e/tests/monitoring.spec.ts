/**
 * Phase 1: continuous monitoring through the real UI, the real scheduler and real e-mail
 * (captured by the local mailpit sink).
 *   baseline scan → daily schedule → the owner fixes the exposed .env → the SCHEDULED scan runs
 *   → compare shows it Fixed + a "fixed" e-mail (en) → the .env comes back → compare shows
 *   "Came back" + a change alert in the account's language (tr) → an identical rescan sends
 *   nothing → the trend lists every scan → the alerts page refuses a non-Slack webhook.
 * Alerts never contain evidence or secrets.
 */
import { expect, test, type Page } from "@playwright/test";
import { expectFinishedReport, fill, newSignedInUser, readField } from "./flows";
import {
  DEMO_RAW_SECRET,
  DEMO_TARGET,
  mailsTo,
  psql,
  publishOwnershipToken,
  removeOwnershipToken,
  resetLocalRateLimits,
  runSchedulerTick,
  setDemoEnvExposed,
  type CapturedMail,
} from "./support";

test.describe.configure({ mode: "serial" });
test.setTimeout(420_000);

const PROJECT = "Demo (monitoring)";
const ENV_TITLE_EN = "Environment file is publicly downloadable: /.env";
const ENV_TITLE_TR = "Ortam değişkeni dosyası herkese açık: /.env";

test.beforeAll(() => {
  if (process.env.E2E_LOCAL_STACK !== "0") resetLocalRateLimits();
  setDemoEnvExposed(true);
  removeOwnershipToken();
});
test.afterAll(() => {
  setDemoEnvExposed(true);
  removeOwnershipToken();
});

async function waitForMail(address: string, subject: string, count = 1): Promise<CapturedMail> {
  let hit: CapturedMail[] = [];
  await expect(async () => {
    hit = mailsTo(address).filter((m) => m.subject === subject);
    expect(hit.length).toBeGreaterThanOrEqual(count);
  }).toPass({ timeout: 90_000, intervals: [2_000] });
  return hit[0];
}

function expectSafeAlert(mail: CapturedMail) {
  expect(mail.text).not.toContain(DEMO_RAW_SECRET);
  expect(mail.text).not.toContain("****"); // no evidence at all, not even masked
  expect(mail.text).toContain("/account/projects/");
}

async function latestCompare(page: Page, projectUrl: string) {
  await page.goto(projectUrl);
  await page
    .getByRole("link", { name: /^Compare/ })
    .first()
    .click();
  await page.waitForURL(/\/compare\/[0-9a-f-]+/);
  await expect(page.getByRole("heading", { name: "What changed", level: 1 })).toBeVisible();
}

async function rescanAndWait(page: Page, projectUrl: string) {
  await page.goto(projectUrl);
  await page.getByRole("button", { name: "Rescan" }).click();
  await page.waitForURL(/\/account\/scans\/[0-9a-f-]+$/);
  await expect(page.getByText("Scan complete")).toBeVisible({ timeout: 150_000 });
}

test("monitoring: scheduled scan, diff, alerts in the user's language, no spam", async ({
  page,
}) => {
  const user = await newSignedInUser(page, "e2e-mon");

  // a verified project with a baseline scan
  await page.goto("/account");
  await fill(page.getByLabel("Project name"), PROJECT);
  await fill(page.getByLabel("Website address"), DEMO_TARGET);
  await page.getByRole("button", { name: "Add project" }).click();
  await page.waitForURL(/\/account\/projects\/[0-9a-f-]+$/);
  const projectUrl = page.url();
  const projectId = projectUrl.split("/").pop() as string;
  publishOwnershipToken(await readField(page, "File content (verification code)"));
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect(page.getByText(/Ownership verified on/)).toBeVisible({ timeout: 60_000 });
  removeOwnershipToken(); // the proof stays valid for 30 days; scheduled scans don't need it now
  await page.getByRole("button", { name: "Rescan" }).click();
  await page.waitForURL(/\/account\/scans\/[0-9a-f-]+$/);
  await expectFinishedReport(page);

  // turn on daily monitoring
  await page.goto(projectUrl);
  await page.getByLabel("Daily").check();
  await page.getByRole("button", { name: "Save schedule" }).click();
  await expect(page.getByText("Schedule saved.")).toBeVisible();
  await expect(page.getByText(/Next scan: /)).toBeVisible();

  // the owner fixes the leak; the next scheduled run is due now
  setDemoEnvExposed(false);
  psql(`UPDATE projects SET next_scan_at = now() - interval '1 minute' WHERE id = '${projectId}'`);
  expect(runSchedulerTick()).toContain(`started=[UUID('${projectId}')]`);
  await expect(async () => {
    await page.goto(projectUrl);
    const history = page.getByRole("table", { name: /Previous scans/ });
    const row = history.getByRole("row").filter({ hasText: "Scheduled" }).first();
    await expect(row).toContainText("Done", { timeout: 2_000 });
  }).toPass({ timeout: 180_000, intervals: [3_000] });

  await latestCompare(page, projectUrl);
  const fixed = page.getByRole("region", { name: /Fixed/ });
  await expect(fixed.getByText(ENV_TITLE_EN).first()).toBeVisible();
  await expect(page.getByText("No new issues.")).toBeVisible();

  const fixedMail = await waitForMail(user.email, `GuardHub: issues fixed on ${PROJECT}`);
  expect(fixedMail.text).toContain("Powered by HKSolutions");
  expectSafeAlert(fixedMail);

  // the account's language is Turkish from now on: the next alert must be Turkish
  const res = await page.request.patch("/api/v1/auth/me", {
    data: { locale: "tr" },
    headers: { "X-GuardHub-CSRF": "1" },
  });
  expect(res.status()).toBe(200);

  // the leak comes back → "came back" (regression) + a change alert
  setDemoEnvExposed(true);
  await rescanAndWait(page, projectUrl);
  await latestCompare(page, projectUrl);
  await expect(
    page
      .getByRole("region", { name: /Came back/ })
      .getByText(ENV_TITLE_EN)
      .first(),
  ).toBeVisible();

  const changeMail = await waitForMail(
    user.email,
    `GuardHub: ${PROJECT} için güvenlik değişiklikleri`,
  );
  expect(changeMail.text).toContain(ENV_TITLE_TR);
  expect(changeMail.text).toContain("HKSolutions");
  expectSafeAlert(changeMail);

  // nothing changed → nothing is sent
  const before = mailsTo(user.email).length;
  await rescanAndWait(page, projectUrl);
  await page.waitForTimeout(20_000); // generous: the alert job runs within seconds when it runs
  expect(mailsTo(user.email).length).toBe(before);

  // the trend lists every finished scan (accessible table behind the chart)
  await page.goto(projectUrl);
  const trend = page.getByRole("table", { name: "Score after each finished scan, oldest first" });
  await expect(trend.getByRole("row")).toHaveCount(5); // header + 4 scans

  // alerts page: only real Slack incoming webhooks are accepted
  await page.getByRole("link", { name: "Alerts" }).click();
  await expect(page.getByRole("heading", { name: "Alerts", level: 1 })).toBeVisible();
  await fill(page.getByLabel("Slack incoming webhook address"), "https://example.com/hooks/abc");
  await page.getByLabel("Slack incoming webhook address").blur();
  await expect(
    page.getByText("This doesn't look like a Slack incoming webhook.", { exact: false }),
  ).toBeVisible();
  // the server is the real gate (SSRF): look-alike hosts and plain http are refused too
  for (const url of [
    "https://hooks.slack.com.evil.example/services/T000/B000/XXXXXXXXXXXX",
    "http://hooks.slack.com/services/T000/B000/XXXXXXXXXXXX",
    "https://user@hooks.slack.com/services/T000/B000/XXXXXXXXXXXX",
  ]) {
    const put = await page.request.put("/api/v1/account/notifications", {
      data: {
        email_enabled: true,
        notify_new: true,
        notify_regression: true,
        notify_fixed: true,
        slack_webhook_url: url,
      },
      headers: { "X-GuardHub-CSRF": "1" },
    });
    expect(put.status(), url).toBe(422);
    expect((await put.json()).error.code, url).toBe("invalid_slack_webhook");
  }

  // a test e-mail is delivered and recorded, but listed only under "Tests": the real alert
  // history (the default view) keeps exactly the two change alerts
  await page.goto("/account/notifications");
  const mailsBefore = mailsTo(user.email).length;
  await page.getByRole("button", { name: "Send test e-mail" }).click();
  await expect(page.getByText("Test sent.", { exact: false })).toBeVisible();
  await expect(() => expect(mailsTo(user.email).length).toBe(mailsBefore + 1)).toPass({
    timeout: 90_000,
    intervals: [2_000],
  });
  await expect(async () => {
    await page.goto("/account/notifications?show=test");
    const row = page
      .getByRole("table", { name: /Alerts we sent/ })
      .getByRole("row")
      .filter({ hasText: "Test message" });
    await expect(row).toHaveCount(1, { timeout: 2_000 });
    await expect(row).toContainText("Sent");
  }).toPass({ timeout: 60_000, intervals: [2_000] });
  await expect(
    page.getByRole("navigation", { name: "Show" }).getByRole("link", { name: "Tests" }),
  ).toHaveAttribute("aria-current", "page");

  await page
    .getByRole("navigation", { name: "Show" })
    .getByRole("link", { name: "Alerts" })
    .click();
  await page.waitForURL(/\/account\/notifications(#.*)?$/);
  const real = page.getByRole("table", { name: /Alerts we sent/ });
  await expect(real.getByRole("row")).toHaveCount(3); // header + "fixed" + "came back" alerts
  await expect(real.getByText("Test message")).toHaveCount(0);
});
