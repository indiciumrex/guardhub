/**
 * Protected account area (customer panel, Phase 5A): requires a full (MFA-complete) session,
 * checked on the server via GET /auth/me with the visitor's cookie forwarded. Everything here
 * is the customer's own data; the API enforces that with row-level security.
 */
import type { ReactNode } from "react";
import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { LogoutButton } from "@/components/account/LogoutButton";
import { CustomerNav } from "@/components/customer/CustomerNav";
import { requireUser } from "@/lib/auth-server";

export const metadata: Metadata = { robots: { index: false, follow: false } };

export default async function ProtectedAccountLayout({ children }: { children: ReactNode }) {
  const user = await requireUser();
  const t = await getTranslations("account");
  return (
    <div className="gh-container space-y-8 py-8">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <CustomerNav isAdmin={user.role === "admin"} />
        <div className="flex items-center gap-3">
          <span className="gh-muted text-sm">{t("signedInAs", { email: user.email })}</span>
          <LogoutButton />
        </div>
      </div>
      {children}
    </div>
  );
}
