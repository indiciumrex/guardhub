/**
 * Admin area (§8.3): role `admin` AND a full MFA session, checked on the server.
 * Everyone else gets a 404, so the admin area isn't discoverable. The API checks the same rule
 * on every admin endpoint (the admin/customer boundary lives in the backend).
 */
import type { ReactNode } from "react";
import type { Metadata } from "next";
import { AdminNav } from "@/components/admin/AdminNav";
import { requireAdmin } from "@/lib/auth-server";

export const metadata: Metadata = { robots: { index: false, follow: false } };

export default async function AdminLayout({ children }: { children: ReactNode }) {
  await requireAdmin();
  return (
    <div className="gh-container py-8">
      <AdminNav />
      {children}
    </div>
  );
}
