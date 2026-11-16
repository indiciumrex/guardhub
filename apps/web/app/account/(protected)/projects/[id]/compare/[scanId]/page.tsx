/**
 * Compare page: what changed in one finished scan of a project, against the previous finished
 * scan or the one picked with `?against=<scanId>` (GET /scans/{id}/diff, §8.3). Alert e-mails
 * link here. An `against` the API rejects (422 invalid_comparison) falls back to the default
 * comparison with a note, rather than an error page.
 */
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { getFormatter, getLocale, getTranslations } from "next-intl/server";
import { CompareScanPicker, earlierDoneScans } from "@/components/account/CompareScanPicker";
import { ScanDiffView } from "@/components/account/ScanDiffView";
import { Alert } from "@/components/ui/Alert";
import { ApiError } from "@/lib/api";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import type { Project, ScanDiff, ScanSummary } from "@/lib/types";

const SCAN_ID = /^[A-Za-z0-9-]{1,64}$/;

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("compare");
  return { title: t("metaTitle") };
}

export default async function CompareScansPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string; scanId: string }>;
  searchParams: Promise<{ against?: string | string[] }>;
}) {
  const { id, scanId } = await params;
  const { against: againstParam } = await searchParams;
  const against =
    typeof againstParam === "string" && SCAN_ID.test(againstParam) ? againstParam : undefined;
  const locale = await getLocale();
  const projectPath = `/projects/${encodeURIComponent(id)}`;
  const diffPath = `/scans/${encodeURIComponent(scanId)}/diff`;

  const loadDiff = async (): Promise<{ diff: ScanDiff; invalidAgainst: boolean }> => {
    try {
      return {
        diff: await serverApiFetch<ScanDiff>(diffPath, { query: { against, locale } }),
        invalidAgainst: false,
      };
    } catch (error) {
      if (
        against &&
        error instanceof ApiError &&
        error.status === 422 &&
        error.code === "invalid_comparison"
      ) {
        return {
          diff: await serverApiFetch<ScanDiff>(diffPath, { query: { locale } }),
          invalidAgainst: true,
        };
      }
      throw error;
    }
  };
  const [project, scans, { diff, invalidAgainst }] = await loadProtected(() =>
    Promise.all([
      serverApiFetch<Project>(projectPath),
      serverApiFetch<ScanSummary[]>(`${projectPath}/scans`),
      loadDiff(),
    ]),
  );
  if (diff.project_id !== project.id) notFound();

  const t = await getTranslations("compare");
  const tProject = await getTranslations("project");
  const format = await getFormatter();
  const formatDate = (value: string) =>
    format.dateTime(new Date(value), { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" });
  const current = scans.find((scan) => scan.id === diff.scan_id);
  const base = diff.base_scan_id ? scans.find((scan) => scan.id === diff.base_scan_id) : undefined;
  const candidates = earlierDoneScans(scans, diff.scan_id);

  return (
    <div className="max-w-4xl space-y-8">
      <div>
        <Link
          href={`/account/projects/${encodeURIComponent(project.id)}`}
          className="gh-link text-sm"
        >
          {tProject("backToProject")}
        </Link>
        <h1 className="mt-2 text-3xl font-bold">{t("title")}</h1>
        <p className="mt-1 font-semibold">{project.name}</p>
        <p className="gh-muted break-all text-sm">{project.target_url}</p>
        {current ? (
          <p className="gh-muted mt-2 text-sm">
            {base
              ? t("subtitle", {
                  date: formatDate(current.created_at),
                  baseDate: formatDate(base.created_at),
                })
              : t("subtitleBaseline", { date: formatDate(current.created_at) })}
          </p>
        ) : null}
      </div>

      {invalidAgainst ? (
        <Alert tone="info" label={t("noticeLabel")}>
          {t("invalidAgainst")}
        </Alert>
      ) : null}

      <ScanDiffView diff={diff} />

      <CompareScanPicker
        action={`/account/projects/${encodeURIComponent(project.id)}/compare/${encodeURIComponent(diff.scan_id)}`}
        candidates={candidates}
        selectedId={diff.base_scan_id}
      />
    </div>
  );
}
