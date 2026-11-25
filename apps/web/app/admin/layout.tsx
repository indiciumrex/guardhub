/**
 * Admin area (§8.3): role `admin` AND a full MFA session, checked on the server.
 * Everyone else gets a 404, so the admin area isn't discoverable. The API checks the same rule
 * on every admin endpoint (the admin/customer boundary lives in the backend).
 *
 * The console frame: GuardHub mark + "admin console", "Powered by HKSolutions" (§8.1), and the
 * section tabs.
 */
import type { ReactNode } from "react";
import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { AdminNav } from "@/components/admin/AdminNav";
import { ShieldMark } from "@/components/brand/ShieldMark";
import { PoweredBy } from "@/components/brand/PoweredBy";
import { requireAdmin } from "@/lib/auth-server";

export const metadata: Metadata = { robots: { index: false, follow: false } };

export default async function AdminLayout({ children }: { children: ReactNode }) {
  await requireAdmin();
  const t = await getTranslations("adminCenter.console");
  return (
    <div className="gh-container py-6">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <p className="flex items-center gap-2 text-sm font-semibold">
          <ShieldMark className="h-6 w-6 shrink-0" />
          <span>{t("eyebrow")}</span>
        </p>
        <PoweredBy className="text-xs" />
      </div>
      <AdminNav />
      <div className="space-y-10">{children}</div>
    </div>
  );
}
