"use client";
/**
 * The one navigation of the signed-in app (profile prompt item 4): customers and admins see the
 * same sidebar. "New scan" is the primary action at the top, then the scan → result → report
 * flow, then the account, and (for admins) the console in three groups: operations, monitoring,
 * platform. Safety-critical state (kill switch, active testing) stays visible for admins.
 * The current page carries aria-current="page", a filled background and a bar (not colour alone).
 * Below lg the groups fold into a "Menu" disclosure; "New scan" stays visible.
 */
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTranslations } from "next-intl";
import { StatusBadge } from "@/components/admin/Stat";

export interface Safety {
  killEngaged: boolean | null; // null: unknown (treated as a warning, never as "fine")
  activeOn: boolean | null;
}

interface Item {
  href: string;
  label: string;
  match?: (p: string) => boolean;
}

function NavGroup({ title, items, pathname }: { title: string; items: Item[]; pathname: string }) {
  return (
    <div>
      <p className="gh-eyebrow px-3 pb-1">{title}</p>
      <ul className="space-y-0.5">
        {items.map((item) => {
          const current = item.match
            ? item.match(pathname)
            : pathname === item.href || pathname.startsWith(`${item.href}/`);
          return (
            <li key={item.href}>
              <Link
                href={item.href}
                aria-current={current ? "page" : undefined}
                className={`flex min-h-10 items-center rounded-lg border-l-4 px-3 text-sm font-semibold transition-colors ${
                  current
                    ? "border-l-teal-500 bg-navy-900 text-white dark:border-l-navy-950 dark:bg-teal-300 dark:text-navy-950"
                    : "border-l-transparent text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-navy-800"
                }`}
              >
                {item.label}
              </Link>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function SafetyBlock({ safety }: { safety: Safety }) {
  const t = useTranslations("appNav");
  return (
    <Link
      href="/admin/scans#kill-h"
      className="block space-y-1.5 rounded-lg border border-slate-200 p-3 text-xs hover:bg-slate-50 dark:border-navy-800 dark:hover:bg-navy-800"
      aria-label={t("safetyLabel")}
    >
      <span className="gh-eyebrow block">{t("safety")}</span>
      <span className="flex items-center justify-between gap-2">
        <span>{t("killSwitch")}</span>
        {safety.killEngaged === null ? (
          <StatusBadge tone="warn">{t("unknown")}</StatusBadge>
        ) : safety.killEngaged ? (
          <StatusBadge tone="crit">{t("engaged")}</StatusBadge>
        ) : (
          <StatusBadge tone="ok">{t("armed")}</StatusBadge>
        )}
      </span>
      <span className="flex items-center justify-between gap-2">
        <span>{t("activeTesting")}</span>
        {safety.activeOn === null ? (
          <StatusBadge tone="warn">{t("unknown")}</StatusBadge>
        ) : safety.activeOn ? (
          <StatusBadge tone="warn">{t("on")}</StatusBadge>
        ) : (
          <StatusBadge tone="locked">{t("off")}</StatusBadge>
        )}
      </span>
    </Link>
  );
}

export function AppNav({
  isAdmin,
  isSuperAdmin,
  safety,
}: {
  isAdmin: boolean;
  isSuperAdmin: boolean;
  safety: Safety | null;
}) {
  const t = useTranslations("appNav");
  const tc = useTranslations("customer.nav");
  const ta = useTranslations("account");
  const tn = useTranslations("adminCenter.nav");
  const pathname = usePathname();

  const scanning: Item[] = [
    {
      href: "/account",
      label: tc("overview"),
      match: (p) =>
        p === "/account" || p.startsWith("/account/projects") || p.startsWith("/account/scans"),
    },
  ];
  const account: Item[] = [
    { href: "/account/notifications", label: ta("alertsNav") },
    { href: "/account/plan", label: tc("plan") },
    { href: "/account/security", label: tc("security") },
  ];
  const operations: Item[] = [
    { href: "/admin", label: tn("overview"), match: (p) => p === "/admin" },
    { href: "/admin/scans", label: tn("scans") },
    { href: "/admin/findings", label: tn("findings") },
    { href: "/admin/sites", label: tn("sites") },
    { href: "/admin/trusted-domains", label: tn("trustedDomains") },
    ...(isSuperAdmin ? [{ href: "/admin/observe", label: tn("observe") }] : []),
  ];
  const monitoring: Item[] = [
    { href: "/admin/alerts", label: tn("alerts") },
    { href: "/admin/reports", label: tn("reports") },
    { href: "/admin/audit", label: tn("audit") },
  ];
  const platform: Item[] = [
    { href: "/admin/modules", label: tn("modules") },
    { href: "/admin/config", label: tn("config") },
    { href: "/admin/integrations", label: tn("integrations") },
    { href: "/admin/billing", label: tn("billing") },
    { href: "/admin/users", label: tn("users") },
  ];
  const newScanCurrent = pathname.startsWith("/account/new-scan");

  const groups = (
    <div className="space-y-5">
      <NavGroup title={t("scanning")} items={scanning} pathname={pathname} />
      <NavGroup title={t("account")} items={account} pathname={pathname} />
      {isAdmin ? (
        <>
          <NavGroup title={t("operations")} items={operations} pathname={pathname} />
          <NavGroup title={t("monitoring")} items={monitoring} pathname={pathname} />
          <NavGroup title={t("platform")} items={platform} pathname={pathname} />
        </>
      ) : null}
    </div>
  );

  return (
    <nav aria-label={t("label")} className="space-y-4 print:hidden">
      <Link
        href="/account/new-scan"
        aria-current={newScanCurrent ? "page" : undefined}
        className="gh-btn-primary w-full text-base shadow-sm"
      >
        <svg viewBox="0 0 20 20" className="h-5 w-5" aria-hidden="true" focusable="false">
          <path
            fill="currentColor"
            d="M8.5 2a6.5 6.5 0 0 1 5.2 10.4l4 4-1.4 1.4-4-4A6.5 6.5 0 1 1 8.5 2Zm0 2a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9Z"
          />
        </svg>
        {t("newScan")}
      </Link>
      {isAdmin && safety ? <SafetyBlock safety={safety} /> : null}
      <div className="hidden lg:block">{groups}</div>
      <details className="gh-panel lg:hidden">
        <summary className="flex min-h-11 cursor-pointer items-center px-4 text-sm font-semibold">
          {t("menu")}
        </summary>
        <div className="border-t border-slate-200 p-3 dark:border-navy-800">{groups}</div>
      </details>
    </nav>
  );
}
