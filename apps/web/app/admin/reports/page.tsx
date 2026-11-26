/**
 * Reports (Admin Panel, Prompt 2 §3): platform, modules, scans, findings, customers and risk
 * trend over 7, 30 or 90 days. Customer data is always masked, on screen and in every export.
 * Exports: CSV and XLSX from the API (audited), PDF through the browser's print dialog.
 */
import type { Metadata } from "next";
import Link from "next/link";
import { getFormatter, getTranslations } from "next-intl/server";
import { PrintReport, ReportScheduleSwitch } from "@/components/admin/ReportControls";
import { PageHeader, Panel, StatusBadge } from "@/components/admin/Stat";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import {
  REPORT_DAYS,
  REPORT_KINDS,
  type ReportKind,
  type ReportSchedule,
  type ReportView,
} from "@/lib/admin-types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("adminCenter.reports");
  return { title: t("title") };
}

type Search = Promise<{ kind?: string; days?: string }>;

export default async function AdminReportsPage({ searchParams }: { searchParams: Search }) {
  const sp = await searchParams;
  const kind: ReportKind = (REPORT_KINDS as readonly string[]).includes(sp.kind ?? "")
    ? (sp.kind as ReportKind)
    : "platform";
  const days = (REPORT_DAYS as readonly number[]).includes(Number(sp.days)) ? Number(sp.days) : 30;
  const [reportR, schedulesR] = await loadProtected(() =>
    Promise.allSettled([
      serverApiFetch<ReportView>(`/admin/reports/${kind}`, { query: { days } }),
      serverApiFetch<ReportSchedule[]>("/admin/report-schedules"),
    ]),
  );
  const report = reportR.status === "fulfilled" ? reportR.value : null;
  const schedules = schedulesR.status === "fulfilled" ? schedulesR.value : [];
  const t = await getTranslations("adminCenter.reports");
  const tConsole = await getTranslations("adminCenter.console");
  const tAdmin = await getTranslations("admin");
  const format = await getFormatter();
  const when = (v: string | null) =>
    v
      ? format.dateTime(new Date(v), { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" })
      : "-";
  const col = (c: string) => (t.has(`columns.${c}`) ? t(`columns.${c}`) : c);
  const href = (k: ReportKind, d: number) => `/admin/reports?kind=${k}&days=${d}`;
  const download = (fmt: "csv" | "xlsx") =>
    `/api/v1/admin/reports/${kind}?days=${days}&format=${fmt}`;
  const scoreCol = report ? report.columns.indexOf("average_score") : -1;
  const pill = (active: boolean) =>
    `inline-flex min-h-9 items-center rounded-full border px-3 text-sm font-semibold ${
      active
        ? "border-navy-900 bg-navy-900 text-white dark:border-teal-300 dark:bg-teal-300 dark:text-navy-950"
        : "border-slate-300 hover:bg-slate-100 dark:border-navy-700 dark:hover:bg-navy-800"
    }`;

  return (
    <>
      <PageHeader eyebrow={tConsole("eyebrow")} title={t("title")} intro={t("intro")} />

      <nav aria-label={t("kindLabel")} className="print:hidden">
        <ul className="flex flex-wrap gap-2">
          {REPORT_KINDS.map((k) => (
            <li key={k}>
              <Link
                href={href(k, days)}
                aria-current={k === kind ? "page" : undefined}
                className={pill(k === kind)}
              >
                {t(`kind.${k}`)}
              </Link>
            </li>
          ))}
        </ul>
        <ul aria-label={t("daysLabel")} className="mt-3 flex flex-wrap gap-2">
          {REPORT_DAYS.map((d) => (
            <li key={d}>
              <Link
                href={href(kind, d)}
                aria-current={d === days ? "page" : undefined}
                className={pill(d === days)}
              >
                {t("days", { days: d })}
              </Link>
            </li>
          ))}
        </ul>
      </nav>

      {!report ? (
        <p className="gh-muted text-sm">{tAdmin("unavailable")}</p>
      ) : (
        <Panel
          id="report-h"
          title={`${t(`kind.${kind}`)} · ${t("days", { days })}`}
          intro={t(`kindHelp.${kind}`)}
          bodyClassName="overflow-x-auto"
          actions={
            <div className="flex flex-wrap items-center gap-2 print:hidden">
              <StatusBadge tone="locked">{t("masked")}</StatusBadge>
              <a className="gh-btn-secondary min-h-9 px-3 py-1.5 text-sm" href={download("csv")}>
                {t("downloadCsv")}
              </a>
              <a className="gh-btn-secondary min-h-9 px-3 py-1.5 text-sm" href={download("xlsx")}>
                {t("downloadXlsx")}
              </a>
              <PrintReport />
            </div>
          }
        >
          <p className="gh-muted px-5 pt-3 text-xs">
            {t("generated", { when: when(report.generated_at) })} ·{" "}
            {t("rowsShown", { shown: report.rows.length, total: report.total_rows })}
            {report.truncated ? ` · ${t("truncated")}` : ""}
          </p>
          {report.rows.length === 0 ? (
            <p className="gh-muted px-5 py-4 text-sm">{t("empty")}</p>
          ) : (
            <table className="gh-table-admin">
              <caption className="sr-only">{t(`kind.${kind}`)}</caption>
              <thead>
                <tr>
                  {report.columns.map((c) => (
                    <th key={c} scope="col" className="whitespace-nowrap">
                      {col(c)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {report.rows.map((row, i) => (
                  <tr key={i}>
                    {row.map((v, j) => (
                      <td
                        key={j}
                        className={`text-xs ${typeof v === "number" ? "tabular-nums" : ""} ${j === 0 ? "font-mono" : ""}`}
                      >
                        {j === scoreCol && typeof v === "number" ? (
                          <span className="inline-flex items-center gap-2">
                            <span
                              aria-hidden="true"
                              className="inline-block h-2 w-24 overflow-hidden rounded-full bg-slate-200 dark:bg-navy-800"
                            >
                              <span
                                className="block h-full rounded-full bg-teal-700 dark:bg-teal-300"
                                style={{ width: `${Math.max(0, Math.min(100, v))}%` }}
                              />
                            </span>
                            {v}
                          </span>
                        ) : v === null ? (
                          "-"
                        ) : (
                          String(v)
                        )}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      )}

      <Panel id="schedules-h" title={t("schedulesTitle")} intro={t("schedulesIntro")}>
        <ul className="space-y-3">
          {schedules.map((s) => (
            <li key={s.frequency}>
              <ReportScheduleSwitch schedule={s} label={t(`schedule.${s.frequency}`)} />
              <p className="gh-muted text-xs">{t("lastSent", { when: when(s.last_sent_at) })}</p>
            </li>
          ))}
        </ul>
      </Panel>
    </>
  );
}
