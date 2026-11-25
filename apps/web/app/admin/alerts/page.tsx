/**
 * Operational alerts (Admin Panel, Prompt 2 §2): open alerts first and most prominent, then the
 * channels, the rules (threshold, window, e-mail, escalation, mute) and the recent alerts.
 * Alerts are always recorded here; e-mail goes to every admin when an alert opens.
 */
import type { Metadata } from "next";
import { getFormatter, getTranslations } from "next-intl/server";
import { OpsAlertActions, OpsAlertRuleForm } from "@/components/admin/OpsAlertControls";
import { PageHeader, Panel, StatusBadge, type Tone } from "@/components/admin/Stat";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import type { OpsAlert, OpsAlertsView } from "@/lib/admin-types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("adminCenter.alerts");
  return { title: t("title") };
}

const KIND_TONE: Record<OpsAlert["kind"], Tone> = {
  critical_finding: "crit",
  scan_failures: "warn",
  worker_offline: "crit",
  api_errors: "warn",
};

export default async function AdminAlertsPage() {
  const [viewR] = await loadProtected(() =>
    Promise.allSettled([serverApiFetch<OpsAlertsView>("/admin/alerts")]),
  );
  const view = viewR.status === "fulfilled" ? viewR.value : null;
  const t = await getTranslations("adminCenter.alerts");
  const tConsole = await getTranslations("adminCenter.console");
  const tAdmin = await getTranslations("admin");
  const format = await getFormatter();
  const when = (v: string | null) =>
    v
      ? format.dateTime(new Date(v), { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" })
      : "-";
  const statusBadge = (a: OpsAlert) =>
    a.status === "open" ? (
      <StatusBadge tone={KIND_TONE[a.kind]}>{t("status.open")}</StatusBadge>
    ) : a.status === "acknowledged" ? (
      <StatusBadge tone="info">{t("status.acknowledged")}</StatusBadge>
    ) : (
      <StatusBadge tone="ok">
        {a.resolved_automatically ? t("status.autoResolved") : t("status.resolved")}
      </StatusBadge>
    );

  return (
    <>
      <PageHeader eyebrow={tConsole("eyebrow")} title={t("title")} intro={t("intro")} />
      {!view ? (
        <p className="gh-muted text-sm">{tAdmin("unavailable")}</p>
      ) : (
        <>
          <Panel
            id="open-h"
            title={t("openTitle")}
            emphasis={view.open.length ? "crit" : "ok"}
            actions={
              view.open.length ? (
                <StatusBadge tone="crit" size="lg">
                  {t("openCount", { count: view.open.length })}
                </StatusBadge>
              ) : (
                <StatusBadge tone="ok">{t("noOpen")}</StatusBadge>
              )
            }
          >
            {view.open.length === 0 ? (
              <p className="gh-muted text-sm">{t("allClear")}</p>
            ) : (
              <ul className="divide-y divide-slate-200 dark:divide-navy-800">
                {view.open.map((a) => (
                  <li
                    key={a.id}
                    className="flex flex-wrap items-start justify-between gap-3 py-3 first:pt-0"
                  >
                    <div className="min-w-0 space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        {statusBadge(a)}
                        <span className="font-semibold">{t(`kind.${a.kind}`)}</span>
                      </div>
                      <p className="text-sm">
                        {t("valueVsThreshold", { value: a.value, threshold: a.threshold })}
                      </p>
                      <p className="gh-muted text-xs">
                        {t("openedAt", { when: when(a.opened_at) })} ·{" "}
                        {t("lastSeen", { when: when(a.last_seen_at) })}
                      </p>
                      <div className="flex flex-wrap gap-2 text-xs">
                        {a.emailed_at ? (
                          <StatusBadge tone={a.email_error ? "warn" : "neutral"}>
                            {a.email_error ? t("emailFailed") : t("emailed")}
                          </StatusBadge>
                        ) : null}
                        {a.escalated_at ? (
                          <StatusBadge tone="crit">{t("escalated")}</StatusBadge>
                        ) : null}
                      </div>
                    </div>
                    <OpsAlertActions alertId={a.id} acknowledged={a.status === "acknowledged"} />
                  </li>
                ))}
              </ul>
            )}
            <p className="gh-muted mt-3 text-xs">{t("resolveNote")}</p>
          </Panel>

          <Panel id="channels-h" title={t("channelsTitle")}>
            <ul className="space-y-2 text-sm">
              <li className="flex flex-wrap items-center gap-2">
                <StatusBadge tone="ok">{t("inAppOn")}</StatusBadge>
                <span className="gh-muted text-xs">{t("inAppDetail")}</span>
              </li>
              <li className="flex flex-wrap items-center gap-2">
                <StatusBadge tone={view.email_configured ? "ok" : "warn"}>
                  {view.email_configured ? t("emailOn") : t("emailOff")}
                </StatusBadge>
                <span className="gh-muted text-xs">
                  {t("recipients", { count: view.admin_recipients })}
                </span>
              </li>
            </ul>
          </Panel>

          <Panel id="rules-h" title={t("rulesTitle")} intro={t("rulesIntro")}>
            <ul className="divide-y divide-slate-200 dark:divide-navy-800">
              {view.rules.map((r) => (
                <li key={r.kind} className="space-y-2 py-4 first:pt-0 last:pb-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-semibold">{t(`kind.${r.kind}`)}</span>
                    {r.enabled ? (
                      <StatusBadge tone="ok">{t("ruleEnabled")}</StatusBadge>
                    ) : (
                      <StatusBadge tone="neutral">{t("ruleDisabled")}</StatusBadge>
                    )}
                    {r.muted_until ? (
                      <StatusBadge tone="warn">
                        {t("mutedUntil", { when: when(r.muted_until) })}
                      </StatusBadge>
                    ) : null}
                  </div>
                  <p className="gh-muted text-xs">{t(`ruleHelp.${r.kind}`)}</p>
                  <OpsAlertRuleForm rule={r} label={t(`kind.${r.kind}`)} />
                </li>
              ))}
            </ul>
          </Panel>

          <Panel id="recent-h" title={t("recentTitle")} bodyClassName="overflow-x-auto">
            {view.recent.length === 0 ? (
              <p className="gh-muted px-5 py-4 text-sm">{t("noRecent")}</p>
            ) : (
              <table className="gh-table-admin">
                <caption className="sr-only">{t("recentTitle")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t("colKind")}</th>
                    <th scope="col">{t("colStatus")}</th>
                    <th scope="col">{t("colValue")}</th>
                    <th scope="col">{t("colOpened")}</th>
                    <th scope="col">{t("colClosed")}</th>
                  </tr>
                </thead>
                <tbody>
                  {view.recent.map((a) => (
                    <tr key={a.id}>
                      <td className="text-sm">{t(`kind.${a.kind}`)}</td>
                      <td>{statusBadge(a)}</td>
                      <td className="text-xs tabular-nums">
                        {a.value} / {a.threshold}
                      </td>
                      <td className="text-xs whitespace-nowrap">{when(a.opened_at)}</td>
                      <td className="text-xs whitespace-nowrap">{when(a.resolved_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>
        </>
      )}
    </>
  );
}
