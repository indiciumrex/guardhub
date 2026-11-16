/**
 * Severity badge: a distinct icon shape + a text label, so severity is never conveyed by
 * colour alone (WCAG 1.4.1).
 */
import { useTranslations } from "next-intl";
import type { Severity } from "@/lib/types";

export const SEVERITY_ORDER: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

const classes: Record<Severity, string> = {
  critical:
    "border-red-300 bg-red-50 text-red-800 dark:border-red-700 dark:bg-red-950 dark:text-red-200",
  high: "border-orange-300 bg-orange-50 text-orange-900 dark:border-orange-700 dark:bg-orange-950 dark:text-orange-200",
  medium:
    "border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200",
  low: "border-sky-300 bg-sky-50 text-sky-900 dark:border-sky-700 dark:bg-sky-950 dark:text-sky-200",
  info: "border-slate-300 bg-slate-50 text-slate-800 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-200",
};

// Different shapes per level: octagon, triangle, diamond, circle, "i".
const iconPaths: Record<Severity, string> = {
  critical: "M7 2h6l5 5v6l-5 5H7l-5-5V7l5-5Zm2 4v5h2V6H9Zm0 6v2h2v-2H9Z",
  high: "M10 2 19 18H1L10 2Zm-1 6v4h2V8H9Zm0 5v2h2v-2H9Z",
  medium: "M10 1.5 18.5 10 10 18.5 1.5 10 10 1.5Zm-1 5v4h2v-4H9Zm0 5v2h2v-2H9Z",
  low: "M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14Zm0 4a3 3 0 1 1 0 6 3 3 0 0 1 0-6Z",
  info: "M10 2a8 8 0 1 0 0 16 8 8 0 0 0 0-16Zm-1 3.5h2v2H9v-2Zm0 3.5h2v6H9V9Z",
};

export function SeverityIcon({
  severity,
  className = "h-4 w-4",
}: {
  severity: Severity;
  className?: string;
}) {
  return (
    <svg viewBox="0 0 20 20" className={className} aria-hidden="true" focusable="false">
      <path fill="currentColor" fillRule="evenodd" d={iconPaths[severity]} />
    </svg>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const t = useTranslations("severity");
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold ${classes[severity]}`}
    >
      <SeverityIcon severity={severity} />
      <span>{t(severity)}</span>
    </span>
  );
}

export function severityClasses(severity: Severity): string {
  return classes[severity];
}
