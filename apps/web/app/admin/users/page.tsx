/**
 * Users & sessions (Admin Panel, Prompt 2 §5). Plain admin / customer split (no role matrix):
 * the role and the data boundary are enforced by the API (RLS + admin session), never by this
 * page. The security policy comes first, then invitations, accounts and failed sign-ins.
 */
import type { Metadata } from "next";
import { getFormatter, getTranslations } from "next-intl/server";
import { AccountActions, InviteAdmin, RevokeInvite } from "@/components/admin/PeopleControls";
import { PageHeader, Panel, StatusBadge, type Tone } from "@/components/admin/Stat";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import type { AdminAccount, AdminInviteView, FailedSignIns } from "@/lib/admin-types";
import { listItems, type ListPayload } from "@/lib/types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("adminCenter.people");
  return { title: t("title") };
}

const INVITE_TONE: Record<AdminInviteView["status"], Tone> = {
  pending: "info",
  accepted: "ok",
  expired: "neutral",
  revoked: "locked",
};

export default async function AdminUsersPage() {
  const [usersR, invitesR, failedR, meR] = await loadProtected(() =>
    Promise.allSettled([
      serverApiFetch<ListPayload<AdminAccount>>("/admin/users", {
        query: { limit: 200, offset: 0 },
      }),
      serverApiFetch<AdminInviteView[]>("/admin/people/invites"),
      serverApiFetch<FailedSignIns>("/admin/people/security/failed-sign-ins", {
        query: { hours: 24 },
      }),
      serverApiFetch<{ id: string }>("/auth/me"),
    ]),
  );
  const users = usersR.status === "fulfilled" ? listItems(usersR.value) : null;
  const invites = invitesR.status === "fulfilled" ? invitesR.value : null;
  const failed = failedR.status === "fulfilled" ? failedR.value : null;
  const meId = meR.status === "fulfilled" ? meR.value.id : null;
  const t = await getTranslations("adminCenter.people");
  const tConsole = await getTranslations("adminCenter.console");
  const tAdmin = await getTranslations("admin");
  const format = await getFormatter();
  const when = (v: string | null) =>
    v
      ? format.dateTime(new Date(v), { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" })
      : "-";

  return (
    <>
      <PageHeader eyebrow={tConsole("eyebrow")} title={t("title")} intro={t("intro")} />

      <Panel
        id="policy-h"
        title={t("policyTitle")}
        emphasis="locked"
        actions={<StatusBadge tone="locked">{t("enforced")}</StatusBadge>}
      >
        <ul className="space-y-2 text-sm">
          {(["mfa", "adminMfa", "disabled", "invites", "rbac"] as const).map((k) => (
            <li key={k} className="flex gap-2">
              <span aria-hidden="true">•</span>
              <span>{t(`policy.${k}`)}</span>
            </li>
          ))}
        </ul>
      </Panel>

      <Panel id="invites-h" title={t("invitesTitle")} intro={t("invitesIntro")}>
        <InviteAdmin />
        {invites && invites.length ? (
          <div className="mt-4 overflow-x-auto">
            <table className="gh-table-admin">
              <caption className="sr-only">{t("invitesTitle")}</caption>
              <thead>
                <tr>
                  <th scope="col">{t("colEmail")}</th>
                  <th scope="col">{t("colStatus")}</th>
                  <th scope="col">{t("colExpires")}</th>
                  <th scope="col">
                    <span className="sr-only">{t("revokeInvite")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {invites.map((i) => (
                  <tr key={i.id}>
                    <th scope="row" className="text-sm font-normal">
                      {i.email}
                    </th>
                    <td>
                      <StatusBadge tone={INVITE_TONE[i.status]}>
                        {t(`invite.${i.status}`)}
                      </StatusBadge>
                    </td>
                    <td className="text-xs whitespace-nowrap">{when(i.expires_at)}</td>
                    <td>
                      {i.status === "pending" ? (
                        <RevokeInvite inviteId={i.id} email={i.email} />
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </Panel>

      <Panel id="accounts-h" title={t("accountsTitle")} bodyClassName="overflow-x-auto">
        {!users ? (
          <p className="gh-muted px-5 py-4 text-sm">{tAdmin("unavailable")}</p>
        ) : (
          <table className="gh-table-admin min-w-[60rem]">
            <caption className="sr-only">{t("accountsTitle")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("colEmail")}</th>
                <th scope="col">{t("colRole")}</th>
                <th scope="col">{t("colStatus")}</th>
                <th scope="col">{t("colTwoFactor")}</th>
                <th scope="col">{t("colLastSignIn")}</th>
                <th scope="col">{t("colSessions")}</th>
                <th scope="col">{t("colActions")}</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id}>
                  <th scope="row" className="text-sm font-medium">
                    {u.email}
                    <span className="gh-muted block text-xs font-normal">
                      {t("joined", { when: when(u.created_at) })}
                    </span>
                  </th>
                  <td>
                    <StatusBadge tone={u.role === "admin" ? "info" : "neutral"}>
                      {t(`role.${u.role}`)}
                    </StatusBadge>
                  </td>
                  <td>
                    {u.disabled_at ? (
                      <StatusBadge tone="locked">{t("disabled")}</StatusBadge>
                    ) : (
                      <StatusBadge tone="ok">{t("active")}</StatusBadge>
                    )}
                  </td>
                  <td>
                    <StatusBadge tone={u.totp_enabled ? "ok" : "warn"}>
                      {u.totp_enabled ? t("mfaOn") : t("mfaPending")}
                    </StatusBadge>
                  </td>
                  <td className="text-xs whitespace-nowrap">{when(u.last_login_at)}</td>
                  <td className="text-xs tabular-nums">{u.sessions}</td>
                  <td>
                    <AccountActions
                      userId={u.id}
                      email={u.email}
                      disabled={Boolean(u.disabled_at)}
                      isSelf={u.id === meId}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel
        id="failed-h"
        title={t("failedTitle")}
        intro={t("failedIntro")}
        emphasis={failed && failed.total >= 20 ? "warn" : undefined}
        actions={
          failed ? (
            <StatusBadge tone={failed.total ? "warn" : "ok"}>
              {t("failedTotal", { count: failed.total })}
            </StatusBadge>
          ) : null
        }
      >
        {!failed ? (
          <p className="gh-muted text-sm">{tAdmin("unavailable")}</p>
        ) : failed.total === 0 ? (
          <p className="gh-muted text-sm">{t("noFailed")}</p>
        ) : (
          <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
            <div>
              <h3 className="text-sm font-semibold">{t("byAccount")}</h3>
              <ul className="mt-2 space-y-1 text-sm">
                {Object.entries(failed.by_account).map(([account, n]) => (
                  <li key={account} className="flex justify-between gap-3">
                    <span className="truncate">
                      {account === "unknown" ? t("unknownAccount") : account}
                    </span>
                    <span className="tabular-nums">{n}</span>
                  </li>
                ))}
              </ul>
            </div>
            <div className="overflow-x-auto">
              <table className="gh-table-admin">
                <caption className="sr-only">{t("failedTitle")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t("colWhen")}</th>
                    <th scope="col">{t("colAccount")}</th>
                    <th scope="col">{t("colKind")}</th>
                    <th scope="col">{t("colIp")}</th>
                  </tr>
                </thead>
                <tbody>
                  {failed.recent.map((f, i) => (
                    <tr key={i}>
                      <td className="text-xs whitespace-nowrap">{when(f.at)}</td>
                      <td className="text-xs">{f.account ?? t("unknownAccount")}</td>
                      <td className="text-xs">{t(`kind.${f.kind}`)}</td>
                      <td className="font-mono text-xs">{f.ip_hash || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </Panel>
    </>
  );
}
