/**
 * Customer security (Phase 5A): two-factor recovery codes and the account's own sessions.
 */
import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { RecoveryCodesPanel } from "@/components/account/RecoveryCodes";
import { PageHeader, Panel, StatusBadge } from "@/components/admin/Stat";
import { OwnSessions } from "@/components/customer/OwnSessions";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import type { AccountSession } from "@/lib/admin-types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("customer.security");
  return { title: t("title") };
}

export default async function AccountSecurityPage() {
  const [recovery, sessions] = await loadProtected(() =>
    Promise.all([
      serverApiFetch<{ remaining: number }>("/auth/2fa/recovery-codes"),
      serverApiFetch<AccountSession[]>("/auth/sessions"),
    ]),
  );
  const t = await getTranslations("customer.security");
  const tc = await getTranslations("customer");
  return (
    <>
      <PageHeader eyebrow={tc("eyebrow")} title={t("title")} intro={t("intro")} />
      <Panel
        id="mfa-h"
        title={t("mfaTitle")}
        emphasis="ok"
        actions={<StatusBadge tone="ok">{t("mfaOn")}</StatusBadge>}
      >
        <p className="text-sm">{t("mfaHelp")}</p>
      </Panel>
      <RecoveryCodesPanel remaining={recovery.remaining} />
      <Panel id="sessions-h" title={t("sessionsTitle")} intro={t("sessionsIntro")}>
        <OwnSessions sessions={sessions} />
      </Panel>
    </>
  );
}
