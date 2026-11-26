/**
 * Profile and security (Phase 5A; profile prompt item 1): the holder's own display name and
 * password (current password + a current two-factor code), recovery codes and own sessions.
 * Admins use the same page for their own account.
 */
import type { Metadata } from "next";
import { getFormatter, getTranslations } from "next-intl/server";
import { ChangePasswordForm, DisplayNameForm } from "@/components/account/ProfileForms";
import { RecoveryCodesPanel } from "@/components/account/RecoveryCodes";
import { PageHeader, Panel, StatusBadge } from "@/components/admin/Stat";
import { OwnSessions } from "@/components/customer/OwnSessions";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected, requireUser } from "@/lib/auth-server";
import type { AccountSession } from "@/lib/admin-types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("customer.security");
  return { title: t("title") };
}

export default async function AccountSecurityPage() {
  const user = await requireUser();
  const [recovery, sessions] = await loadProtected(() =>
    Promise.all([
      serverApiFetch<{ remaining: number }>("/auth/2fa/recovery-codes"),
      serverApiFetch<AccountSession[]>("/auth/sessions"),
    ]),
  );
  const t = await getTranslations("customer.security");
  const tc = await getTranslations("customer");
  const tp = await getTranslations("profile");
  const format = await getFormatter();
  return (
    <>
      <PageHeader eyebrow={tc("eyebrow")} title={t("title")} intro={t("intro")} />
      <Panel id="profile-h" title={tp("title")} intro={tp("intro")}>
        <dl className="mb-4 grid gap-1 text-sm sm:grid-cols-[10rem_1fr]">
          <dt className="gh-muted">{tp("email")}</dt>
          <dd className="font-mono">{user.email}</dd>
          <dt className="gh-muted">{tp("role")}</dt>
          <dd>{user.role === "admin" ? tp("roleAdmin") : tp("roleCustomer")}</dd>
        </dl>
        <DisplayNameForm current={user.display_name ?? null} />
        <p className="gh-muted mt-2 text-xs">{tp("emailHelp")}</p>
      </Panel>
      <Panel
        id="password-h"
        title={tp("passwordTitle")}
        intro={
          user.password_changed_at
            ? tp("lastChanged", {
                when: format.dateTime(new Date(user.password_changed_at), {
                  dateStyle: "medium",
                  timeStyle: "short",
                  timeZone: "UTC",
                }),
              })
            : tp("neverChanged")
        }
      >
        <ChangePasswordForm />
      </Panel>
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
