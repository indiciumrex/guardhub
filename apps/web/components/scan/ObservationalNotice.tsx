/**
 * The label every observe-only scan carries (super-admin, no ownership proof): a badge next to
 * the heading and a note saying what that means, so the report can never be mistaken for a
 * verified, full scan. Shown on the live view, the final report and in print.
 */
import { useTranslations } from "next-intl";

export function ObservationalBadge() {
  const t = useTranslations("scanLive.observational");
  return (
    <span className="inline-flex items-center rounded-full border-2 border-amber-600 bg-amber-50 px-2.5 py-0.5 text-xs font-bold uppercase tracking-wide text-amber-900 dark:border-amber-400 dark:bg-navy-900 dark:text-amber-200 print:border-black print:text-black">
      {t("badge")}
    </span>
  );
}

export function ObservationalNotice() {
  const t = useTranslations("scanLive.observational");
  return (
    <section
      aria-label={t("badge")}
      className="rounded-lg border-2 border-amber-600 bg-amber-50 px-4 py-3 text-sm text-amber-950 dark:border-amber-400 dark:bg-navy-900 dark:text-amber-100 print:border-black print:bg-white print:text-black"
    >
      <p className="font-bold">{t("title")}</p>
      <p className="mt-1">{t("body")}</p>
    </section>
  );
}
