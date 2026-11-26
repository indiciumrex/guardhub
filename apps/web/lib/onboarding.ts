/**
 * Customer onboarding (Phase 5A): the steps from sign-up to the first report, computed only from
 * the customer's own data (the API scopes it by row-level security). No step can be skipped
 * around ownership proof: a site is scanned only after it is verified (§9.2).
 */
import type { NotificationSettings, Project, Severity } from "@/lib/types";

export type StepKey = "account" | "site" | "verify" | "scan" | "review" | "alerts";

export interface Step {
  key: StepKey;
  done: boolean;
  href: string;
}

const SERIOUS: Severity[] = ["critical", "high"];

export function onboardingSteps(projects: Project[], alerts: NotificationSettings | null): Step[] {
  const first = projects[0];
  const verified = projects.find((p) => p.verified);
  const scanned = projects.find((p) => p.last_scan?.status === "done");
  const unverified = projects.find((p) => !p.verified) ?? first;
  return [
    { key: "account", done: true, href: "/account/security" },
    { key: "site", done: projects.length > 0, href: "/account#add-site" },
    {
      key: "verify",
      done: Boolean(verified),
      href: unverified ? `/account/projects/${unverified.id}` : "/account#add-site",
    },
    {
      key: "scan",
      done: Boolean(scanned),
      href: verified ? "/account/new-scan" : "/account#add-site",
    },
    {
      key: "review",
      done: Boolean(scanned),
      href: scanned?.last_scan ? `/account/scans/${scanned.last_scan.id}` : "/account",
    },
    {
      key: "alerts",
      done: Boolean(alerts && (alerts.email_enabled || alerts.slack_configured)),
      href: "/account/notifications",
    },
  ];
}

export interface RiskSummary {
  sites: number;
  verified: number;
  scanned: number;
  open: Record<Severity, number>;
  serious: number;
  lowestScore: { project: Project; score: number } | null;
}

const ZERO: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

/** Open findings from each site's latest completed scan, and the weakest site. */
export function riskSummary(projects: Project[]): RiskSummary {
  const open = { ...ZERO };
  let lowest: RiskSummary["lowestScore"] = null;
  let scanned = 0;
  for (const p of projects) {
    const s = p.last_scan;
    if (!s || s.status !== "done") continue;
    scanned += 1;
    for (const sev of Object.keys(open) as Severity[]) open[sev] += s.finding_counts?.[sev] ?? 0;
    if (s.score !== null && (lowest === null || s.score < lowest.score)) {
      lowest = { project: p, score: s.score };
    }
  }
  return {
    sites: projects.length,
    verified: projects.filter((p) => p.verified).length,
    scanned,
    open,
    serious: SERIOUS.reduce((n, sev) => n + open[sev], 0),
    lowestScore: lowest,
  };
}
