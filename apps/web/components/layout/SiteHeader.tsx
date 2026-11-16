/**
 * Site header: logo, primary navigation and the language selector. Rendered by the root
 * layout, so it appears on every page (including error and not-found pages).
 */
import Link from "next/link";
import { useLocale, useTranslations } from "next-intl";
import { Logo } from "@/components/brand/Logo";
import { isLocale, DEFAULT_LOCALE } from "@/lib/i18n/config";
import { LanguageSwitcher } from "./LanguageSwitcher";

export function SiteHeader() {
  const t = useTranslations("nav");
  const rawLocale = useLocale();
  const locale = isLocale(rawLocale) ? rawLocale : DEFAULT_LOCALE;
  return (
    <header className="border-b border-slate-200 bg-white/90 dark:border-navy-800 dark:bg-navy-950/90">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded focus:bg-white focus:px-3 focus:py-2 focus:text-navy-900"
      >
        {t("skipToContent")}
      </a>
      <div className="gh-container flex flex-wrap items-center justify-between gap-3 py-3">
        <Link href="/" aria-label={t("home")} className="rounded-md">
          <Logo />
        </Link>
        <nav aria-label={t("primary")} className="flex flex-wrap items-center gap-1 sm:gap-3">
          <Link
            href="/scan"
            className="rounded-md px-3 py-2 text-sm font-semibold text-navy-900 hover:bg-slate-100 dark:text-slate-100 dark:hover:bg-navy-800"
          >
            {t("scan")}
          </Link>
          <Link
            href="/account"
            className="rounded-md px-3 py-2 text-sm font-semibold text-navy-900 hover:bg-slate-100 dark:text-slate-100 dark:hover:bg-navy-800"
          >
            {t("account")}
          </Link>
          <LanguageSwitcher currentLocale={locale} />
        </nav>
      </div>
    </header>
  );
}
