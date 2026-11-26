import { describe, expect, it } from "vitest";
import type { NotificationSettings, Project } from "@/lib/types";
import { onboardingSteps, riskSummary } from "./onboarding";

const counts = (critical: number, high: number) => ({ critical, high, medium: 1, low: 0, info: 2 });

function project(
  id: string,
  verified: boolean,
  scan: null | { score: number; c: number; h: number },
): Project {
  return {
    id,
    name: id,
    kind: "site",
    repo_full_name: null,
    target_url: `https://${id}.example`,
    verified,
    ownership_verified_at: verified ? "2026-11-26T00:00:00Z" : null,
    verification: {} as Project["verification"],
    last_scan: scan
      ? ({
          id: `scan-${id}`,
          project_id: id,
          status: "done",
          score: scan.score,
          finding_counts: counts(scan.c, scan.h),
          created_at: "2026-11-26T00:00:00Z",
        } as unknown as Project["last_scan"])
      : null,
    created_at: "2026-11-25T00:00:00Z",
    scan_frequency: "off",
    next_scan_at: null,
    schedule_paused_reason: null,
  };
}

const alertsOn = { email_enabled: true, slack_configured: false } as NotificationSettings;

describe("onboardingSteps", () => {
  it("starts at adding a website", () => {
    const steps = onboardingSteps([], null);
    expect(steps.map((s) => [s.key, s.done])).toEqual([
      ["account", true],
      ["site", false],
      ["verify", false],
      ["scan", false],
      ["review", false],
      ["alerts", false],
    ]);
  });

  it("asks to verify before any scan, and points at the unverified site", () => {
    const steps = onboardingSteps([project("a", false, null)], alertsOn);
    const verify = steps.find((s) => s.key === "verify");
    expect(verify).toEqual({ key: "verify", done: false, href: "/account/projects/a" });
    expect(steps.find((s) => s.key === "scan")?.done).toBe(false);
  });

  it("is complete once a verified site has a finished scan and alerts are on", () => {
    const steps = onboardingSteps([project("a", true, { score: 80, c: 0, h: 1 })], alertsOn);
    expect(steps.every((s) => s.done)).toBe(true);
    expect(steps.find((s) => s.key === "review")?.href).toBe("/account/scans/scan-a");
  });
});

describe("riskSummary", () => {
  it("adds up open findings and finds the weakest site", () => {
    const r = riskSummary([
      project("a", true, { score: 92, c: 0, h: 1 }),
      project("b", true, { score: 55, c: 2, h: 3 }),
      project("c", false, null),
    ]);
    expect(r.sites).toBe(3);
    expect(r.verified).toBe(2);
    expect(r.scanned).toBe(2);
    expect(r.serious).toBe(6);
    expect(r.open.medium).toBe(2);
    expect(r.lowestScore?.project.id).toBe("b");
  });
});
