/**
 * What changed between two finished scans of a project (docs/architecture.md §8.3): score now
 * vs before with the difference in words, then New / Came back / Fixed lists (severity badge,
 * title, one-line summary, link to the full report), the unchanged count, and the checks that
 * were left out because they could not run in one of the scans. When the scan is the project's
 * first finished one (`base_scan_id === null`) it shows the baseline state instead.
 */
import Link from "next/link";
import { useTranslations } from "next-intl";
import type { DiffItem, ScanDiff } from "@/lib/types";
import { SeverityBadge } from "@/components/scan/SeverityBadge";

type SectionKind = "new" | "regressed" | "fixed";

function DiffSection({
  kind,
  items,
  reportHref,
  reportLabel,
}: {
  kind: SectionKind;
  items: DiffItem[];
  reportHref: string;
  reportLabel: string;
}) {
  const t = useTranslations("compare");
  const headingId = `diff-${kind}-heading`;
  return (
    <section aria-labelledby={headingId} className="space-y-3">
      <div>
        <h2 id={headingId} className="text-xl font-semibold">
          {t(`${kind}Heading`)}{" "}
          <span className="tabular-nums">{t("count", { count: items.length })}</span>
        </h2>
        <p className="gh-muted text-sm">{t(`${kind}Intro`)}</p>
      </div>
      {items.length === 0 ? (
        <p className="gh-muted text-sm">{t(`${kind}Empty`)}</p>
      ) : (
        <ul className="space-y-3">
          {items.map((item) => (
            <li key={item.fingerprint} className="gh-card space-y-2 p-4">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={item.severity} />
                <h3 className="font-semibold">{item.title}</h3>
              </div>
              <p className="text-sm">{item.summary}</p>
              <Link href={reportHref} className="gh-link text-sm">
                {reportLabel}
                <span className="sr-only"> {t("reportFor", { title: item.title })}</span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function ScoreDelta({ delta }: { delta: number }) {
  const t = useTranslations("compare");
  if (delta === 0) {
    return <span className="font-semibold">{t("deltaSame")}</span>;
  }
  const up = delta > 0;
  return (
    <span
      className={`inline-flex items-center gap-1 font-semibold ${
        up ? "text-emerald-800 dark:text-emerald-200" : "text-red-800 dark:text-red-200"
      }`}
    >
      <span aria-hidden="true">{up ? "▲" : "▼"}</span>
      {up ? t("deltaUp", { delta }) : t("deltaDown", { delta: Math.abs(delta) })}
    </span>
  );
}

export function ScanDiffView({ diff }: { diff: ScanDiff }) {
  const t = useTranslations("compare");
  const tChecks = useTranslations("checks");
  const checkName = (id: string) => (tChecks.has(`${id}.name`) ? tChecks(`${id}.name`) : id);
  const currentReport = `/account/scans/${encodeURIComponent(diff.scan_id)}`;

  return (
    <div className="space-y-10">
      <section aria-labelledby="diff-score-heading" className="gh-card p-5">
        <h2 id="diff-score-heading" className="text-xl font-semibold">
          {t("scoreHeading")}
        </h2>
        <dl className="mt-3 flex flex-wrap items-end gap-x-10 gap-y-3">
          <div>
            <dt className="gh-muted text-sm">{t("scoreNow")}</dt>
            <dd className="text-3xl font-bold tabular-nums">
              {diff.score} <span className="gh-muted text-sm font-normal">{t("outOf")}</span>
            </dd>
          </div>
          {diff.base_score !== null ? (
            <div>
              <dt className="gh-muted text-sm">{t("scoreBefore")}</dt>
              <dd className="text-3xl font-bold tabular-nums">
                {diff.base_score} <span className="gh-muted text-sm font-normal">{t("outOf")}</span>
              </dd>
            </div>
          ) : null}
          {diff.score_delta !== null ? (
            <div>
              <dt className="sr-only">{t("scoreChange")}</dt>
              <dd>
                <ScoreDelta delta={diff.score_delta} />
              </dd>
            </div>
          ) : null}
        </dl>
      </section>

      {diff.base_scan_id === null ? (
        <section
          aria-labelledby="diff-baseline-heading"
          className="rounded-lg border border-sky-300 bg-sky-50 px-4 py-3 text-sky-950 dark:border-sky-800 dark:bg-sky-950/60 dark:text-sky-100"
        >
          <h2 id="diff-baseline-heading" className="font-semibold">
            {t("baselineTitle")}
          </h2>
          <p className="mt-1 text-sm">{t("baselineBody")}</p>
          <p className="mt-1 text-sm">{t("baselineFound", { count: diff.unchanged_count })}</p>
          <p className="mt-2 text-sm">
            <Link href={currentReport} className="gh-link">
              {t("viewReport")}
            </Link>
          </p>
        </section>
      ) : (
        <>
          <DiffSection
            kind="new"
            items={diff.new}
            reportHref={currentReport}
            reportLabel={t("viewReport")}
          />
          <DiffSection
            kind="regressed"
            items={diff.regressed}
            reportHref={currentReport}
            reportLabel={t("viewReport")}
          />
          <DiffSection
            kind="fixed"
            items={diff.fixed}
            reportHref={`/account/scans/${encodeURIComponent(diff.base_scan_id)}`}
            reportLabel={t("viewEarlierReport")}
          />
          <p className="text-sm">{t("unchanged", { count: diff.unchanged_count })}</p>
        </>
      )}

      {diff.skipped_checks.length > 0 ? (
        <section
          aria-labelledby="diff-skipped-heading"
          className="rounded-lg border border-slate-300 px-4 py-3 text-sm dark:border-navy-700"
        >
          <h2 id="diff-skipped-heading" className="font-semibold">
            {t("skippedTitle")}
          </h2>
          <p className="mt-1">{t("skippedBody")}</p>
          <ul className="mt-2 list-disc space-y-1 pl-5">
            {diff.skipped_checks.map((checkId) => (
              <li key={checkId}>{checkName(checkId)}</li>
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  );
}
