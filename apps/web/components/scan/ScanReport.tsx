/**
 * The plain-language scan report, shared by the free scan and the account area:
 * score, severity counts, then finding cards (most severe first), or a positive result.
 */
import type { ReactNode } from "react";
import { useFormatter, useTranslations } from "next-intl";
import type { ScanView } from "@/lib/types";
import { hostOf } from "@/lib/navigation";
import { FindingCard } from "./FindingCard";
import { ScoreGauge } from "./ScoreGauge";
import { SEVERITY_ORDER } from "./SeverityBadge";
import { SeverityCounts } from "./SeverityCounts";

export function ScanReport({ scan, actions }: { scan: ScanView; actions?: ReactNode }) {
  const t = useTranslations("report");
  const format = useFormatter();
  const findings = [...scan.findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );
  const failedChecks = scan.progress.filter((item) => item.status === "failed");
  const finishedAt = scan.finished_at ?? scan.created_at;

  return (
    <div className="space-y-8">
      <section aria-labelledby="report-heading" className="gh-card p-6 sm:p-8">
        <div className="flex flex-col gap-8 md:flex-row md:items-center">
          {scan.score !== null ? <ScoreGauge score={scan.score} /> : null}
          <div className="flex-1 space-y-4">
            <div>
              <h2 id="report-heading" className="text-2xl font-bold">
                {t("heading", { host: hostOf(scan.target_url) })}
              </h2>
              <p className="gh-muted mt-1 text-sm">
                {t("scannedAt", {
                  date: format.dateTime(new Date(finishedAt), {
                    dateStyle: "medium",
                    timeStyle: "short",
                    timeZone: "UTC",
                  }),
                })}
              </p>
            </div>
            <div>
              <h3 className="mb-2 text-sm font-semibold">{t("countsHeading")}</h3>
              <SeverityCounts counts={scan.finding_counts} />
            </div>
            {actions ? <div className="flex flex-wrap gap-3 pt-2">{actions}</div> : null}
          </div>
        </div>
        {failedChecks.length > 0 ? (
          <p className="mt-6 rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-950 dark:border-amber-700 dark:bg-amber-950/50 dark:text-amber-100">
            {t("partial", {
              names: failedChecks.map((item) => item.name || item.check_id).join(", "),
            })}
          </p>
        ) : null}
      </section>

      <section aria-labelledby="findings-heading">
        <h2 id="findings-heading" className="mb-4 text-xl font-bold">
          {t("findingsHeading", { count: findings.length })}
        </h2>
        {findings.length === 0 ? (
          <div className="gh-card flex items-start gap-4 border-emerald-300 p-6 dark:border-emerald-800">
            <svg
              viewBox="0 0 20 20"
              className="h-8 w-8 shrink-0 text-emerald-700 dark:text-emerald-300"
              aria-hidden="true"
              focusable="false"
            >
              <path
                fill="currentColor"
                d="M10 2a8 8 0 1 0 0 16 8 8 0 0 0 0-16Zm-1.2 11.4L5.3 9.9l1.4-1.4 2.1 2.1 4.5-4.5 1.4 1.4-5.9 5.9Z"
              />
            </svg>
            <div>
              <h3 className="text-lg font-semibold">{t("cleanTitle")}</h3>
              <p className="gh-muted mt-1">{t("cleanBody")}</p>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            {findings.map((finding) => (
              <FindingCard key={finding.id} finding={finding} />
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
