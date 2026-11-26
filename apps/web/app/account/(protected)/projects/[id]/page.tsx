/**
 * Project page: ownership verification (instructions + "Verify"), the automatic scan schedule
 * (§8.2), the score trend (§8.3), "Rescan", and the scan history (date, trigger, score, counts,
 * status, report and compare links).
 */
import type { Metadata } from "next";
import Link from "next/link";
import { getFormatter, getTranslations } from "next-intl/server";
import { RescanButton, VerifyProjectButton } from "@/components/account/ProjectActions";
import { ScheduleControl } from "@/components/account/ScheduleControl";
import {
  CustomerActiveTesting,
  type ActiveReadiness,
} from "@/components/customer/CustomerActiveTesting";
import { ScoreTrendChart } from "@/components/account/ScoreTrendChart";
import { ScanStatusBadge } from "@/components/account/ScanStatusBadge";
import { OwnershipInstructions } from "@/components/scan/OwnershipInstructions";
import { SeverityCounts } from "@/components/scan/SeverityCounts";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import { isScanActive, type Project, type ScanSummary, type TrendPoint } from "@/lib/types";

const TREND_LIMIT = 30;

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("project");
  return { title: t("metaTitle") };
}

export default async function ProjectPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const projectPath = `/projects/${encodeURIComponent(id)}`;
  const [project, scans, trend, active] = await loadProtected(() =>
    Promise.all([
      serverApiFetch<Project>(projectPath),
      serverApiFetch<ScanSummary[]>(`${projectPath}/scans`),
      serverApiFetch<TrendPoint[]>(`${projectPath}/trend`, { query: { limit: TREND_LIMIT } }),
      serverApiFetch<ActiveReadiness>(`${projectPath}/active`).catch(() => null),
    ]),
  );
  const tActive = await getTranslations("customerActive");
  const t = await getTranslations("project");
  const tGitHub = await getTranslations("github");
  const tSchedule = await getTranslations("schedule");
  const tTrend = await getTranslations("trend");
  const tCompare = await getTranslations("compare");
  const format = await getFormatter();
  const scanInProgress = scans.some((scan) => isScanActive(scan.status));
  const formatDate = (value: string) =>
    format.dateTime(new Date(value), { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" });
  // The oldest finished scan has nothing before it, so it gets no "Compare" link.
  const doneScans = scans.filter((scan) => scan.status === "done");
  const oldestDoneId = doneScans.at(-1)?.id ?? null;

  return (
    <div className="space-y-10">
      <div>
        <Link href="/account" className="gh-link text-sm">
          {t("back")}
        </Link>
        <h1 className="mt-2 text-3xl font-bold">{project.name}</h1>
        <p className="gh-muted mt-1 break-all">{project.target_url}</p>
      </div>

      <section aria-labelledby="ownership-heading" className="space-y-4">
        <h2 id="ownership-heading" className="text-xl font-semibold">
          {t("ownershipHeading")}
        </h2>
        {project.kind === "repo" ? (
          project.verified ? (
            <p className="rounded-lg border border-emerald-300 bg-emerald-50 px-4 py-3 text-sm text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-100">
              {project.ownership_verified_at
                ? tGitHub("repoConnectedOn", { date: formatDate(project.ownership_verified_at) })
                : tGitHub("repoConnected")}
            </p>
          ) : (
            <p className="rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950/50 dark:text-amber-100">
              {tGitHub("repoAccessLost")}{" "}
              <Link href="/account#github" className="gh-link">
                {tGitHub("backToAccount")}
              </Link>
            </p>
          )
        ) : project.verified ? (
          <p className="rounded-lg border border-emerald-300 bg-emerald-50 px-4 py-3 text-sm text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-100">
            {project.ownership_verified_at
              ? t("verifiedOn", { date: formatDate(project.ownership_verified_at) })
              : t("verifiedPlain")}
          </p>
        ) : (
          <>
            <OwnershipInstructions
              token={project.verification.token}
              instructions={project.verification}
            />
            <VerifyProjectButton projectId={project.id} />
          </>
        )}
      </section>

      {active && project.kind !== "repo" ? (
        <section aria-labelledby="active-heading" className="gh-panel">
          <div className="gh-panel-head">
            <div>
              <h2 id="active-heading" className="text-base font-semibold">
                {tActive("title")}
              </h2>
              <p className="gh-muted mt-0.5 text-xs">{tActive("intro")}</p>
            </div>
          </div>
          <div className="gh-panel-body">
            <CustomerActiveTesting projectId={project.id} readiness={active} />
          </div>
        </section>
      ) : null}

      <section aria-labelledby="schedule-heading" className="space-y-4">
        <div>
          <h2 id="schedule-heading" className="text-xl font-semibold">
            {tSchedule("heading")}
          </h2>
          <p className="gh-muted mt-1 text-sm">{tSchedule("intro")}</p>
        </div>
        <ScheduleControl
          projectId={project.id}
          verified={project.verified}
          initial={{
            scan_frequency: project.scan_frequency,
            next_scan_at: project.next_scan_at,
            schedule_paused_reason: project.schedule_paused_reason,
          }}
        />
      </section>

      <section aria-labelledby="trend-heading" className="space-y-4">
        <div>
          <h2 id="trend-heading" className="text-xl font-semibold">
            {tTrend("heading")}
          </h2>
          <p className="gh-muted mt-1 text-sm">{tTrend("intro")}</p>
        </div>
        <ScoreTrendChart points={trend} />
      </section>

      <section aria-labelledby="history-heading" className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 id="history-heading" className="text-xl font-semibold">
            {t("historyHeading")}
          </h2>
          <RescanButton projectId={project.id} disabled={!project.verified || scanInProgress} />
        </div>
        {!project.verified ? (
          <p className="gh-muted text-sm">
            {project.kind === "repo" ? tGitHub("repoAccessLost") : t("rescanNeedsVerification")}
          </p>
        ) : null}
        {scanInProgress ? <p className="gh-muted text-sm">{t("scanInProgress")}</p> : null}
        {scans.length === 0 ? (
          <p className="gh-muted">{t("noScans")}</p>
        ) : (
          <div className="gh-card overflow-x-auto">
            <table className="gh-table">
              <caption className="sr-only">{t("historyCaption")}</caption>
              <thead>
                <tr>
                  <th scope="col">{t("colDate")}</th>
                  <th scope="col">{tTrend("colTrigger")}</th>
                  <th scope="col">{t("colScore")}</th>
                  <th scope="col">{t("colFindings")}</th>
                  <th scope="col">{t("colStatus")}</th>
                  <th scope="col">
                    <span className="sr-only">{t("colReport")}</span>
                  </th>
                  <th scope="col">
                    <span className="sr-only">{tCompare("colCompare")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.id}>
                    <td className="whitespace-nowrap">{formatDate(scan.created_at)}</td>
                    <td className="whitespace-nowrap">{tTrend(`trigger.${scan.trigger}`)}</td>
                    <td className="tabular-nums">{scan.score ?? t("noScore")}</td>
                    <td>
                      <SeverityCounts counts={scan.finding_counts} compact />
                    </td>
                    <td>
                      <ScanStatusBadge status={scan.status} />
                    </td>
                    <td>
                      <Link
                        href={`/account/scans/${scan.id}`}
                        className="gh-link whitespace-nowrap"
                      >
                        {t("viewReport")}
                        <span className="sr-only"> {formatDate(scan.created_at)}</span>
                      </Link>
                    </td>
                    <td>
                      {scan.status === "done" && scan.id !== oldestDoneId ? (
                        <Link
                          href={`/account/projects/${encodeURIComponent(project.id)}/compare/${encodeURIComponent(scan.id)}`}
                          className="gh-link whitespace-nowrap"
                          aria-label={tCompare("historyLinkLabel", {
                            date: formatDate(scan.created_at),
                          })}
                        >
                          {tCompare("historyLink")}
                        </Link>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
