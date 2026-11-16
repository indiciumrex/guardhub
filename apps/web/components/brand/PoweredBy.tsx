/**
 * "Powered by HKSolutions" line, shown on every screen (§8.1).
 */
import { useTranslations } from "next-intl";
import { COMPANY_NAME } from "./Logo";

export function PoweredBy({ className = "" }: { className?: string }) {
  const t = useTranslations("brand");
  return (
    <p className={`text-sm text-slate-600 dark:text-slate-300 ${className}`}>
      {t.rich("poweredBy", {
        company: COMPANY_NAME,
        strong: (chunks) => (
          <strong className="font-semibold text-navy-900 dark:text-slate-100">{chunks}</strong>
        ),
      })}
    </p>
  );
}
