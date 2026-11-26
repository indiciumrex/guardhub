/**
 * Customer panel overview (Phase 5A): the onboarding steps until the first report, the risk
 * summary across the customer's own sites, the sites themselves and adding a new one.
 * Sign-up → add a site → prove ownership (§9.2) → passive scan → findings and risk → report and
 * alerts. Everything shown is the customer's own data (row-level security in the API).
 */
import type { Metadata } from "next";
import Link from "next/link";
import { getFormatter, getTranslations } from "next-intl/server";
import { AddProjectForm } from "@/components/account/AddProjectForm";
import { GitHubSection } from "@/components/account/GitHubSection";
import { PageHeader, Panel, Stat, StatusBadge, type Tone } from "@/components/admin/Stat";
import { SeverityIcon } from "@/components/scan/SeverityBadge";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import { onboardingSteps, riskSummary } from "@/lib/onboarding";
import type { GitHubStatus, NotificationSettings, Project, Severity } from "@/lib/types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("customer");
  return { title: t("title") };
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

function scoreTone(score: number | null): Tone {
  if (score === null) return "neutral";
  return score >= 90 ? "ok" : score >= 70 ? "warn" : "crit";
}

export default async function AccountHomePage() {
  const [projects, github, alerts] = await loadProtected(() =>
    Promise.all([
      serverApiFetch<Project[]>("/projects"),
      serverApiFetch<GitHubStatus>("/github"),
      serverApiFetch<NotificationSettings>("/account/notifications").catch(() => null),
    ]),
  );
  const t = await getTranslations("customer");
  const tAccount = await getTranslations("account");
  const tGitHub = await getTranslations("github");
  const tSev = await getTranslations("severity");
  const format = await getFormatter();
  const when = (v: string | null) =>
    v ? format.dateTime(new Date(v), { dateStyle: "medium", timeZone: "UTC" }) : "-";

  const steps = onboardingSteps(projects, alerts);
  const done = steps.filter((s) => s.done).length;
  const nextStep = steps.find((s) => !s.done);
  const risk = riskSummary(projects);

  return (
    <>
      <PageHeader eyebrow={t("eyebrow")} title={t("title")} intro={t("intro")} />

      <Panel
        id="onboarding-h"
        title={t("onboardingTitle")}
        intro={t("onboardingProgress", { done, total: steps.length })}
        emphasis={nextStep ? "info" : "ok"}
        actions={
          nextStep ? (
            <Link href={nextStep.href} className="gh-btn-primary min-h-9 px-3 py-1.5 text-sm">
              {t(`step.${nextStep.key}.cta`)}
            </Link>
          ) : (
            <StatusBadge tone="ok">{t("allSet")}</StatusBadge>
          )
        }
      >
        <ol aria-label={t("onboardingTitle")} className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {steps.map((s, i) => (
            <li
              key={s.key}
              className={`rounded-lg border p-3 ${
                s.key === nextStep?.key
                  ? "border-sky-400 dark:border-sky-600"
                  : "border-slate-200 dark:border-navy-800"
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-semibold">
                  {i + 1}. {t(`step.${s.key}.title`)}
                </span>
                <StatusBadge tone={s.done ? "ok" : "neutral"}>
                  {s.done ? t("stepDone") : t("stepTodo")}
                </StatusBadge>
              </div>
              <p className="gh-muted mt-1 text-xs">{t(`step.${s.key}.help`)}</p>
              {!s.done ? (
                <Link href={s.href} className="gh-link mt-2 inline-block text-xs">
                  {t(`step.${s.key}.cta`)}
                </Link>
              ) : null}
            </li>
          ))}
        </ol>
      </Panel>

      <section aria-labelledby="risk-h" className="space-y-3">
        <h2 id="risk-h" className="text-lg font-semibold tracking-tight">
          {t("riskTitle")}
        </h2>
        <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Stat label={t("sites")} value={risk.sites} />
          <Stat
            label={t("verifiedSites")}
            value={risk.verified}
            tone={risk.verified ? "ok" : undefined}
          />
          <Stat
            label={t("seriousOpen")}
            value={risk.serious}
            tone={risk.serious ? "crit" : risk.scanned ? "ok" : undefined}
            hint={t("seriousHint")}
          />
          <Stat
            label={t("weakest")}
            value={risk.lowestScore ? `${risk.lowestScore.score}/100` : "-"}
            tone={risk.lowestScore ? scoreTone(risk.lowestScore.score) : undefined}
            hint={risk.lowestScore?.project.name}
          />
        </dl>
        {risk.scanned ? (
          <ul aria-label={t("openBySeverity")} className="flex flex-wrap gap-2 text-sm">
            {SEVERITIES.map((sev) => (
              <li key={sev} className="gh-panel inline-flex items-center gap-2 px-3 py-1.5">
                <SeverityIcon severity={sev} className="h-3.5 w-3.5" />
                {tSev(sev)}: <span className="font-semibold tabular-nums">{risk.open[sev]}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="gh-muted text-sm">{t("noScansYet")}</p>
        )}
      </section>

      <Panel id="sites-h" title={tAccount("projectsHeading")} bodyClassName="overflow-x-auto">
        {projects.length === 0 ? (
          <p className="gh-muted px-5 py-4 text-sm">{tAccount("noProjects")}</p>
        ) : (
          <table className="gh-table-admin">
            <caption className="sr-only">{tAccount("projectsHeading")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("colSite")}</th>
                <th scope="col">{t("colOwnership")}</th>
                <th scope="col">{t("colLastScan")}</th>
                <th scope="col">{t("colScore")}</th>
                <th scope="col">{t("colSerious")}</th>
                <th scope="col">{t("colNext")}</th>
              </tr>
            </thead>
            <tbody>
              {projects.map((p) => {
                const s = p.last_scan;
                const serious = s
                  ? (s.finding_counts?.critical ?? 0) + (s.finding_counts?.high ?? 0)
                  : 0;
                return (
                  <tr key={p.id}>
                    <th scope="row" className="text-sm font-medium">
                      <Link href={`/account/projects/${p.id}`} className="gh-link">
                        {p.name}
                      </Link>
                      <span className="gh-muted block text-xs font-normal break-all">
                        {p.kind === "repo" ? `${tGitHub("repoLabel")}: ` : null}
                        {p.target_url}
                      </span>
                    </th>
                    <td>
                      {p.verified ? (
                        <StatusBadge tone="ok">{tAccount("verified")}</StatusBadge>
                      ) : (
                        <Link href={`/account/projects/${p.id}`} className="gh-link text-xs">
                          <StatusBadge tone="warn">{t("verifyNow")}</StatusBadge>
                        </Link>
                      )}
                    </td>
                    <td className="text-xs whitespace-nowrap">
                      {s ? (
                        <Link href={`/account/scans/${s.id}`} className="gh-link">
                          {when(s.created_at)}
                        </Link>
                      ) : (
                        tAccount("neverScanned")
                      )}
                    </td>
                    <td>
                      {s && s.score !== null ? (
                        <StatusBadge tone={scoreTone(s.score)}>{s.score}/100</StatusBadge>
                      ) : (
                        "-"
                      )}
                    </td>
                    <td className="text-xs tabular-nums">
                      {s ? (
                        <StatusBadge tone={serious ? "crit" : "ok"}>{serious}</StatusBadge>
                      ) : (
                        "-"
                      )}
                    </td>
                    <td className="text-xs whitespace-nowrap">
                      {p.scan_frequency === "off" ? t("noSchedule") : when(p.next_scan_at)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Panel>

      <div className="grid gap-6 lg:grid-cols-2">
        <section id="add-site" aria-labelledby="add-heading" className="gh-panel">
          <div className="gh-panel-head">
            <div>
              <h2 id="add-heading" className="text-base font-semibold">
                {tAccount("addHeading")}
              </h2>
              <p className="gh-muted mt-0.5 text-xs">{tAccount("addIntro")}</p>
            </div>
          </div>
          <div className="gh-panel-body">
            <AddProjectForm />
          </div>
        </section>
        <section id="github" aria-labelledby="github-heading" className="gh-panel">
          <div className="gh-panel-head">
            <h2 id="github-heading" className="text-base font-semibold">
              {tGitHub("heading")}
            </h2>
          </div>
          <div className="gh-panel-body">
            <GitHubSection status={github} />
          </div>
        </section>
      </div>
    </>
  );
}
