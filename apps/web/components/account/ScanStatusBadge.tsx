import { useTranslations } from "next-intl";
import type { ScanStatus } from "@/lib/types";

const classes: Record<ScanStatus, string> = {
  queued: "border-slate-300 text-slate-700 dark:border-slate-600 dark:text-slate-200",
  running: "border-sky-300 text-sky-800 dark:border-sky-700 dark:text-sky-200",
  done: "border-emerald-300 text-emerald-800 dark:border-emerald-700 dark:text-emerald-200",
  failed: "border-red-300 text-red-800 dark:border-red-700 dark:text-red-200",
  cancelled: "border-amber-300 text-amber-900 dark:border-amber-700 dark:text-amber-200",
};

/** Scan status as a text badge (colour is only a secondary cue). */
export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  const t = useTranslations("scanStatus");
  return (
    <span
      className={`inline-flex rounded-full border px-2.5 py-0.5 text-xs font-semibold ${classes[status]}`}
    >
      {t(status)}
    </span>
  );
}
