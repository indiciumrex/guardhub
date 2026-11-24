"use client";
/**
 * Admin control centre navigation (§8.3). A plain list of links; the current section carries
 * aria-current="page" and a visible underline (not colour alone).
 */
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTranslations } from "next-intl";

const SECTIONS = [
  { href: "/admin", key: "overview" },
  { href: "/admin/modules", key: "modules" },
  { href: "/admin/scans", key: "scans" },
  { href: "/admin/findings", key: "findings" },
  { href: "/admin/audit", key: "audit" },
  { href: "/admin/users", key: "users" },
  { href: "/admin/trusted-domains", key: "trustedDomains" },
] as const;

export function AdminNav() {
  const t = useTranslations("adminCenter.nav");
  const pathname = usePathname();
  const current = (href: string) =>
    href === "/admin" ? pathname === "/admin" : pathname.startsWith(href);
  return (
    <nav aria-label={t("label")} className="mb-8 overflow-x-auto">
      <ul className="flex min-w-max gap-1 border-b border-slate-200 dark:border-navy-700">
        {SECTIONS.map((s) => (
          <li key={s.href}>
            <Link
              href={s.href}
              aria-current={current(s.href) ? "page" : undefined}
              className={`inline-flex min-h-11 items-center px-3 text-sm font-semibold ${
                current(s.href)
                  ? "border-b-2 border-teal-700 text-teal-800 dark:border-teal-300 dark:text-teal-200"
                  : "gh-muted hover:underline"
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
