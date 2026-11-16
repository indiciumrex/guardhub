import { useTranslations } from "next-intl";
import type { SeverityCounts as Counts } from "@/lib/types";
import { SEVERITY_ORDER, SeverityIcon, severityClasses } from "./SeverityBadge";

export function SeverityCounts({ counts, compact = false }: { counts: Counts; compact?: boolean }) {
  const t = useTranslations("severity");
  return (
    <ul className={`flex flex-wrap ${compact ? "gap-1.5" : "gap-2"}`}>
      {SEVERITY_ORDER.map((severity) => (
        <li
          key={severity}
          className={`inline-flex items-center gap-1.5 rounded-md border font-medium ${
            compact ? "px-1.5 py-0.5 text-xs" : "px-2.5 py-1 text-sm"
          } ${severityClasses(severity)}`}
        >
          <SeverityIcon severity={severity} className={compact ? "h-3 w-3" : "h-4 w-4"} />
          <span className="tabular-nums font-semibold">{counts[severity] ?? 0}</span>
          <span className={compact ? "sr-only" : undefined}>{t(severity)}</span>
        </li>
      ))}
    </ul>
  );
}
