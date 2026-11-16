/**
 * One finding as a "what's exposed + why it matters + how to fix" card (§2.2, §7.3), with the
 * masked evidence in a collapsible block. API text is rendered as text only.
 */
import { useTranslations } from "next-intl";
import type { FindingView } from "@/lib/types";
import { FixSteps } from "./FixSteps";
import { SeverityBadge } from "./SeverityBadge";

const accent: Record<FindingView["severity"], string> = {
  critical: "border-l-red-600",
  high: "border-l-orange-500",
  medium: "border-l-amber-500",
  low: "border-l-sky-500",
  info: "border-l-slate-400",
};

export function FindingCard({ finding }: { finding: FindingView }) {
  const t = useTranslations("finding");
  const headingId = `finding-${finding.id}`;
  return (
    <article
      aria-labelledby={headingId}
      className={`gh-card border-l-4 p-5 sm:p-6 ${accent[finding.severity]}`}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <h3 id={headingId} className="text-lg font-semibold text-navy-950 dark:text-white">
          {finding.title}
        </h3>
        <div className="flex flex-wrap gap-2">
          <SeverityBadge severity={finding.severity} />
          {finding.status !== "open" ? (
            <span className="inline-flex items-center rounded-full border border-slate-300 px-2.5 py-0.5 text-xs font-semibold dark:border-slate-600">
              {t(`status.${finding.status}`)}
            </span>
          ) : null}
        </div>
      </div>

      <dl className="mt-4 space-y-4 text-sm leading-relaxed">
        <div>
          <dt className="font-semibold text-navy-900 dark:text-slate-100">{t("whatsExposed")}</dt>
          <dd className="mt-1 text-slate-700 dark:text-slate-300">{finding.summary}</dd>
        </div>
        <div>
          <dt className="font-semibold text-navy-900 dark:text-slate-100">{t("whyItMatters")}</dt>
          <dd className="mt-1 text-slate-700 dark:text-slate-300">{finding.why}</dd>
        </div>
        <div>
          <dt className="font-semibold text-navy-900 dark:text-slate-100">{t("howToFix")}</dt>
          <dd className="mt-1 text-slate-700 dark:text-slate-300">
            <FixSteps fix={finding.fix} />
          </dd>
        </div>
      </dl>

      <details className="mt-4 rounded-lg border border-slate-200 bg-slate-50 dark:border-navy-700 dark:bg-navy-950">
        <summary className="cursor-pointer rounded-lg px-4 py-2 text-sm font-semibold text-navy-900 dark:text-slate-100">
          {t("evidence")}
        </summary>
        <div className="space-y-2 px-4 pb-4 text-sm">
          <p className="gh-muted">{t("evidenceNote")}</p>
          <dl className="grid gap-x-4 gap-y-1 sm:grid-cols-[max-content_1fr]">
            <dt className="font-semibold">{t("evidenceKind")}</dt>
            <dd>
              {t.has(`evidenceKinds.${finding.evidence.kind}`)
                ? t(`evidenceKinds.${finding.evidence.kind}`)
                : finding.evidence.kind}
            </dd>
            <dt className="font-semibold">{t("evidenceLocation")}</dt>
            <dd className="break-all font-mono text-xs">{finding.evidence.location}</dd>
          </dl>
          <pre className="max-h-64 overflow-auto rounded-md bg-white p-3 font-mono text-xs whitespace-pre-wrap break-all text-navy-950 dark:bg-navy-900 dark:text-slate-100">
            {finding.evidence.redacted_payload}
          </pre>
        </div>
      </details>
    </article>
  );
}
