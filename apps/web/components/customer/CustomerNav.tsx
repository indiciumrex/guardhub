"use client";
/**
 * Customer panel navigation (Phase 5A): the customer's own sections, separate from the admin
 * console. The current tab carries aria-current="page", a filled background and an underline.
 */
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTranslations } from "next-intl";

export function CustomerNav({ isAdmin }: { isAdmin: boolean }) {
  const t = useTranslations("account");
  const tc = useTranslations("customer.nav");
  const pathname = usePathname();
  const sections = [
    {
      href: "/account",
      label: tc("overview"),
      match: (p: string) =>
        p === "/account" || p.startsWith("/account/projects") || p.startsWith("/account/scans"),
    },
    {
      href: "/account/notifications",
      label: t("alertsNav"),
      match: (p: string) => p.startsWith("/account/notifications"),
    },
    {
      href: "/account/plan",
      label: tc("plan"),
      match: (p: string) => p.startsWith("/account/plan"),
    },
    {
      href: "/account/security",
      label: tc("security"),
      match: (p: string) => p.startsWith("/account/security"),
    },
  ];
  return (
    <nav aria-label={t("navLabel")} className="overflow-x-auto">
      <ul className="flex min-w-max gap-1 rounded-xl border border-slate-200 bg-white p-1 shadow-sm dark:border-navy-800 dark:bg-navy-900">
        {sections.map((s) => {
          const current = s.match(pathname);
          return (
            <li key={s.href}>
              <Link
                href={s.href}
                aria-current={current ? "page" : undefined}
                className={`inline-flex min-h-10 items-center rounded-lg px-3.5 text-sm font-semibold transition-colors ${
                  current
                    ? "bg-navy-900 text-white underline decoration-teal-300 decoration-2 underline-offset-[6px] dark:bg-teal-300 dark:text-navy-950 dark:decoration-navy-950"
                    : "text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-navy-800"
                }`}
              >
                {s.label}
              </Link>
            </li>
          );
        })}
        {isAdmin ? (
          <li>
            <Link
              href="/admin"
              className="inline-flex min-h-10 items-center rounded-lg px-3.5 text-sm font-semibold text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-navy-800"
            >
              {t("adminNav")}
            </Link>
          </li>
        ) : null}
      </ul>
    </nav>
  );
}
