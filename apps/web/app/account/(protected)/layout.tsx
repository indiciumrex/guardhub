/**
 * Protected account area: requires a full (MFA-complete) session, checked on the server
 * via GET /auth/me with the visitor's cookie forwarded.
 */
import type { ReactNode } from "react";
import type { Metadata } from "next";
import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { LogoutButton } from "@/components/account/LogoutButton";
import { requireUser } from "@/lib/auth-server";

export const metadata: Metadata = { robots: { index: false, follow: false } };

export default async function ProtectedAccountLayout({ children }: { children: ReactNode }) {
  const user = await requireUser();
  const t = await getTranslations("account");
  return (
    <div className="gh-container py-8">
      <div className="mb-8 flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 pb-4 dark:border-navy-800">
        <nav aria-label={t("navLabel")} className="flex flex-wrap gap-4 text-sm font-semibold">
          <Link href="/account" className="gh-link">
            {t("projectsNav")}
          </Link>
          {user.role === "admin" ? (
            <Link href="/admin" className="gh-link">
              {t("adminNav")}
            </Link>
          ) : null}
        </nav>
        <div className="flex items-center gap-3">
          <span className="gh-muted text-sm">{t("signedInAs", { email: user.email })}</span>
          <LogoutButton />
        </div>
      </div>
      {children}
    </div>
  );
}
