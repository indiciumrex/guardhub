/**
 * Launch gate J: smoke test against the LIVE site (default https://guardhub.dev).
 * Scans only an owned target (SMOKE_TARGET) whose ownership token the test publishes over SSH
 * (SMOKE_SSH, SMOKE_TOKEN_PATH). SMOKE_RAW_SECRET is the fake secret planted on that target;
 * it is passed at run time and never committed.
 */
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./smoke",
  workers: 1,
  retries: 0,
  timeout: 240_000,
  expect: { timeout: 20_000 },
  reporter: [["list"]],
  use: {
    baseURL: process.env.SMOKE_BASE_URL ?? "https://guardhub.dev",
    locale: "en-US",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
