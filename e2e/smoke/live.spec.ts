import { execFileSync } from "node:child_process";
import { expect, test, type Locator, type Page } from "@playwright/test";

const TARGET = process.env.SMOKE_TARGET ?? "https://www.guardhub.dev";
const HOST = new URL(TARGET).host;
const SSH = process.env.SMOKE_SSH ?? "";
const TOKEN_PATH = process.env.SMOKE_TOKEN_PATH ?? "";
const RAW_SECRET = process.env.SMOKE_RAW_SECRET ?? "";

test.describe.configure({ mode: "serial" });

function publishToken(token: string) {
  execFileSync("ssh", ["-o", "BatchMode=yes", SSH, `umask 022; cat > ${TOKEN_PATH}`], {
    input: `${token}\n`,
  });
}

async function fill(input: Locator, value: string) {
  await input.page().waitForLoadState("networkidle");
  await expect(async () => {
    await input.fill(value);
    await expect(input).toHaveValue(value, { timeout: 1_000 });
  }).toPass({ timeout: 20_000 });
}

async function expectMaskedEvidence(page: Page, toggleLabel: string) {
  const evidence = page.locator("details").filter({ hasText: "STRIPE_SECRET_KEY" }).first();
  await expect(evidence.getByText(toggleLabel)).toBeVisible(); // label in the current language
  if ((await evidence.getAttribute("open")) === null) await evidence.getByText(toggleLabel).click();
  await expect(evidence.getByText(/STRIPE_SECRET_KEY=\*\*\*\*9876/)).toBeVisible();
  expect(await page.content()).not.toContain(RAW_SECRET);
}

test("live: owned site scanned with proof, plain report in EN and TR, secrets masked", async ({
  page,
}) => {
  expect(
    SSH && TOKEN_PATH && RAW_SECRET,
    "SMOKE_SSH, SMOKE_TOKEN_PATH, SMOKE_RAW_SECRET",
  ).toBeTruthy();
  publishToken("");
  const scanRequests: string[] = [];
  page.on("request", (r) => {
    if (/\/api\/v1\/public\/scans\//.test(r.url())) scanRequests.push(r.url());
  });

  await page.goto("/scan");
  await fill(page.getByLabel("Your website address"), TARGET);
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByRole("heading", { name: /Prove that you control/ })).toBeVisible();

  // no proof published yet: refused, and no scan exists to poll
  await page.getByRole("button", { name: "Verify & start scan" }).click();
  await expect(
    page.getByText("We couldn't confirm that you control this website yet."),
  ).toBeVisible({ timeout: 60_000 });
  expect(scanRequests).toEqual([]);

  publishToken(await page.getByLabel("File content (verification code)").first().inputValue());
  await page.getByRole("button", { name: "Verify & start scan" }).click();
  await page.waitForURL(/\/scan\/[0-9a-f-]+$/);
  await expect(page.getByText("Scan complete")).toBeVisible({ timeout: 200_000 });
  await expect(page.getByRole("heading", { name: `Security report for ${HOST}` })).toBeVisible();
  await expectMaskedEvidence(page, "Show evidence (masked)");
  await page.screenshot({ path: "test-results/live-report-en.png", fullPage: true });

  await page
    .getByRole("button", { name: /Language|English/ })
    .first()
    .click();
  await page.getByRole("option", { name: "Türkçe" }).click();
  await expect(page.getByRole("heading", { name: `${HOST} için güvenlik raporu` })).toBeVisible();
  await expect(page.getByText("Tarama tamamlandı")).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("lang", "tr");
  await expectMaskedEvidence(page, "Kanıtı göster (maskelenmiş)");
  await page.screenshot({ path: "test-results/live-report-tr.png", fullPage: true });
  publishToken("");
});

test("live: internal and private addresses are refused before anything is queued", async ({
  page,
  request,
}) => {
  for (const internal of [
    "http://redis:6379",
    "http://guardhub-postgres-1:5432",
    "http://localhost:3000",
    "http://127.0.0.1",
    "http://10.0.0.5",
    "http://169.254.169.254/latest/meta-data",
    "http://[::1]",
  ]) {
    const res = await request.post("/api/v1/public/challenges", {
      data: { target_url: internal },
      headers: { "X-GuardHub-CSRF": "1" },
    });
    expect(res.status(), internal).toBe(422);
    expect((await res.json()).error.code, internal).toBe("invalid_target_url");
  }
  await page.goto("/scan");
  await fill(page.getByLabel("Your website address"), "http://redis:6379");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Error" })).toBeVisible();
  await expect(page.getByRole("heading", { name: /Prove that you control/ })).toHaveCount(0);
});
