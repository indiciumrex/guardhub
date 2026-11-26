/**
 * Admin area (§8.3): role `admin` AND a full MFA session, checked on the server.
 * Everyone else gets a 404, so the admin area isn't discoverable. The API checks the same rule
 * on every admin endpoint (the admin/customer boundary lives in the backend).
 *
 * The console uses the same app frame as the customer panel (one navigation, profile prompt
 * item 4), with the console groups, the safety state and "Powered by HKSolutions" (§8.1).
 */
import type { ReactNode } from "react";
import type { Metadata } from "next";
import { AppShell } from "@/components/layout/AppShell";
import { requireAdmin } from "@/lib/auth-server";

export const metadata: Metadata = { robots: { index: false, follow: false } };

export default async function AdminLayout({ children }: { children: ReactNode }) {
  const user = await requireAdmin();
  return (
    <AppShell user={user} console>
      {children}
    </AppShell>
  );
}
