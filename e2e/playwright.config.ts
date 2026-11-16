/**
 * Real-browser E2E against an already running stack (Gate B of the launch checklist).
 *
 * Local:  docker compose -f docker-compose.yml -f docker-compose.demo.yml up -d --build
 *         cd e2e && npm ci && npx playwright install chromium && npm test
 * The journeys scan the bundled demo target (ops/demo-target), so they need the demo override;
 * they never point the scanner at anything else.
 */
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  fullyParallel: false,
  workers: 1, // the journeys share the single demo target and its ownership file
  retries: 0, // a flaky launch gate is a red launch gate
  timeout: 180_000,
  expect: { timeout: 15_000 },
  reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:3000",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    locale: "en-US",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
