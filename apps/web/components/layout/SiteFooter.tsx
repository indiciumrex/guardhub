/**
 * Site footer with the mark and "Powered by HKSolutions" (§8.1).
 */
import { useTranslations } from "next-intl";
import { Logo } from "@/components/brand/Logo";
import { PoweredBy } from "@/components/brand/PoweredBy";

export function SiteFooter() {
  const t = useTranslations("footer");
  const year = new Date().getUTCFullYear();
  return (
    <footer className="mt-16 border-t border-slate-200 bg-white dark:border-navy-800 dark:bg-navy-950">
      <div className="gh-container flex flex-col gap-4 py-8 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <Logo markOnly className="h-7 w-7" />
          <p className="text-sm text-slate-600 dark:text-slate-300">{t("tagline")}</p>
        </div>
        <div className="flex flex-col gap-1 sm:items-end">
          <PoweredBy />
          <p className="text-xs text-slate-600 dark:text-slate-400">{t("copyright", { year })}</p>
        </div>
      </div>
    </footer>
  );
}
