/**
 * Protected account area (customer panel, Phase 5A): requires a full (MFA-complete) session,
 * checked on the server via GET /auth/me with the visitor's cookie forwarded. Everything here
 * is the customer's own data; the API enforces that with row-level security. Same app frame as
 * the admin console (one navigation, "New scan" first: profile prompt item 4).
 */
import type { ReactNode } from "react";
import type { Metadata } from "next";
import { AppShell } from "@/components/layout/AppShell";
import { requireUser } from "@/lib/auth-server";

export const metadata: Metadata = { robots: { index: false, follow: false } };

export default async function ProtectedAccountLayout({ children }: { children: ReactNode }) {
  const user = await requireUser();
  return (
    <AppShell user={user} console={false}>
      {children}
    </AppShell>
  );
}
