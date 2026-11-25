"use client";
/**
 * Admin control centre navigation (§8.3): section tabs. The current tab carries
 * aria-current="page", a filled background and an underline (not colour alone).
 */
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTranslations } from "next-intl";

const SECTIONS = [
  { href: "/admin", key: "overview" },
  { href: "/admin/modules", key: "modules" },
  { href: "/admin/scans", key: "scans" },
  { href: "/admin/findings", key: "findings" },
  { href: "/admin/alerts", key: "alerts" },
  { href: "/admin/audit", key: "audit" },
  { href: "/admin/users", key: "users" },
  { href: "/admin/trusted-domains", key: "trustedDomains" },
  { href: "/admin/config", key: "config" },
] as const;

export function AdminNav() {
  const t = useTranslations("adminCenter.nav");
  const pathname = usePathname();
  const current = (href: string) =>
    href === "/admin" ? pathname === "/admin" : pathname.startsWith(href);
  return (
    <nav aria-label={t("label")} className="mb-8 overflow-x-auto">
      <ul className="flex min-w-max gap-1 rounded-xl border border-slate-200 bg-white p-1 shadow-sm dark:border-navy-800 dark:bg-navy-900">
        {SECTIONS.map((s) => (
          <li key={s.href}>
            <Link
              href={s.href}
              aria-current={current(s.href) ? "page" : undefined}
              className={`inline-flex min-h-10 items-center rounded-lg px-3.5 text-sm font-semibold transition-colors ${
                current(s.href)
                  ? "bg-navy-900 text-white underline decoration-teal-300 decoration-2 underline-offset-[6px] dark:bg-teal-300 dark:text-navy-950 dark:decoration-navy-950"
                  : "text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-navy-800"
              }`}
            >
              {t(s.key)}
            </Link>
          </li>
        ))}
      </ul>
    </nav>
  );
}
