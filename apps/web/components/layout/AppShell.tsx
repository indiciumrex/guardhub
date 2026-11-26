/**
 * The signed-in app frame (profile prompt item 4), shared by the customer panel and the admin
 * console so there is one navigation: the sidebar (AppNav) with "New scan" on top, and the page.
 * For admins it also loads the safety state (kill switch, active testing) and whether this admin
 * is a super-admin (the observe-only page answers 404 otherwise). Both lookups fail closed: an
 * unreadable kill switch shows as "unknown", never as fine.
 */
import type { ReactNode } from "react";
import { getTranslations } from "next-intl/server";
import { LogoutButton } from "@/components/account/LogoutButton";
import { PoweredBy } from "@/components/brand/PoweredBy";
import { ShieldMark } from "@/components/brand/ShieldMark";
import { AppNav, type Safety } from "@/components/layout/AppNav";
import { serverApiFetch } from "@/lib/api-server";
import type { Orchestration } from "@/lib/admin-types";
import type { User } from "@/lib/types";

async function adminState(): Promise<{ safety: Safety; superAdmin: boolean }> {
  const [orch, observe] = await Promise.allSettled([
    serverApiFetch<Orchestration>("/admin/orchestration"),
    serverApiFetch<unknown>("/admin/observe-scans"),
  ]);
  const active = orch.status === "fulfilled" ? orch.value.active : null;
  return {
    safety: {
      killEngaged: active ? active.global_kill : null,
      activeOn: active ? active.effective === "on" : null,
    },
    superAdmin: observe.status === "fulfilled",
  };
}

export async function AppShell({
  user,
  console: inConsole,
  children,
}: {
  user: User;
  console: boolean;
  children: ReactNode;
}) {
  const t = await getTranslations("appNav");
  const ta = await getTranslations("account");
  const isAdmin = user.role === "admin";
  const state = isAdmin ? await adminState() : null;
  return (
    <div className="gh-container py-6 lg:grid lg:grid-cols-[15rem_minmax(0,1fr)] lg:gap-8">
      <aside className="mb-6 space-y-4 lg:sticky lg:top-4 lg:mb-0 lg:self-start">
        <p className="flex items-center gap-2 text-sm font-semibold">
          <ShieldMark className="h-6 w-6 shrink-0" />
          <span>{inConsole ? t("consoleTitle") : t("panelTitle")}</span>
        </p>
        <AppNav
          isAdmin={isAdmin}
          isSuperAdmin={state?.superAdmin ?? false}
          safety={state?.safety ?? null}
        />
        <div className="space-y-2 border-t border-slate-200 pt-4 text-xs dark:border-navy-800">
          {user.display_name ? <p className="font-semibold">{user.display_name}</p> : null}
          <p className="gh-muted break-all">{ta("signedInAs", { email: user.email })}</p>
          <LogoutButton />
          {inConsole ? <PoweredBy className="block pt-2 text-xs" /> : null}
        </div>
      </aside>
      <div className="min-w-0 space-y-8">{children}</div>
    </div>
  );
}
