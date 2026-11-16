/**
 * Project page: ownership verification (instructions + "Verify"), "Rescan", and the scan
 * history (date, score, counts, status, report link).
 */
import type { Metadata } from "next";
import Link from "next/link";
import { getFormatter, getTranslations } from "next-intl/server";
import { RescanButton, VerifyProjectButton } from "@/components/account/ProjectActions";
import { ScanStatusBadge } from "@/components/account/ScanStatusBadge";
import { OwnershipInstructions } from "@/components/scan/OwnershipInstructions";
import { SeverityCounts } from "@/components/scan/SeverityCounts";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import { isScanActive, type Project, type ScanSummary } from "@/lib/types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("project");
  return { title: t("metaTitle") };
}

export default async function ProjectPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const projectPath = `/projects/${encodeURIComponent(id)}`;
  const [project, scans] = await loadProtected(() =>
    Promise.all([
      serverApiFetch<Project>(projectPath),
      serverApiFetch<ScanSummary[]>(`${projectPath}/scans`),
    ]),
  );
  const t = await getTranslations("project");
  const format = await getFormatter();
  const scanInProgress = scans.some((scan) => isScanActive(scan.status));
  const formatDate = (value: string) =>
    format.dateTime(new Date(value), { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" });

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
        {project.verified ? (
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

      <section aria-labelledby="history-heading" className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 id="history-heading" className="text-xl font-semibold">
            {t("historyHeading")}
          </h2>
          <RescanButton projectId={project.id} disabled={!project.verified || scanInProgress} />
        </div>
        {!project.verified ? (
          <p className="gh-muted text-sm">{t("rescanNeedsVerification")}</p>
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
                  <th scope="col">{t("colScore")}</th>
                  <th scope="col">{t("colFindings")}</th>
                  <th scope="col">{t("colStatus")}</th>
                  <th scope="col">
                    <span className="sr-only">{t("colReport")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.id}>
                    <td className="whitespace-nowrap">{formatDate(scan.created_at)}</td>
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
