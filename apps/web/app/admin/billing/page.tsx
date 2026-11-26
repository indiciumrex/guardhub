/**
 * Billing (Admin, Phase 5C): whether charging is live (keys shown only as configured or not),
 * the plan limits, manual plan assignment and the subscriptions. Prices live with the payment
 * provider; turning charging on is the founder's decision, on the server.
 */
import type { Metadata } from "next";
import { getFormatter, getTranslations } from "next-intl/server";
import { PageHeader, Panel, StatusBadge } from "@/components/admin/Stat";
import { AssignPlan, PlanEditor } from "@/components/customer/BillingControls";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import type { AdminBillingView } from "@/lib/admin-types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("billing.admin");
  return { title: t("title") };
}

export default async function AdminBillingPage() {
  const view = await loadProtected(() => serverApiFetch<AdminBillingView>("/admin/billing"));
  const t = await getTranslations("billing.admin");
  const tp = await getTranslations("billing.plan");
  const tConsole = await getTranslations("adminCenter.console");
  const format = await getFormatter();
  const when = (v: string | null) =>
    v ? format.dateTime(new Date(v), { dateStyle: "medium", timeZone: "UTC" }) : "-";
  const set = (ok: boolean) => (
    <StatusBadge tone={ok ? "ok" : "neutral"}>{ok ? t("configured") : t("notSet")}</StatusBadge>
  );
  return (
    <>
      <PageHeader eyebrow={tConsole("eyebrow")} title={t("title")} intro={t("intro")} />
      <Panel
        id="charging-h"
        title={t("chargingTitle")}
        emphasis="locked"
        actions={
          <StatusBadge tone={view.charging_live ? "warn" : "locked"}>
            {view.charging_live ? t("chargingLive") : t("chargingOff")}
          </StatusBadge>
        }
      >
        <dl className="grid gap-2 text-sm sm:grid-cols-2">
          <div className="gh-kv">
            <dt>{t("enabledFlag")}</dt>
            <dd>{set(view.charging_enabled)}</dd>
          </div>
          <div className="gh-kv">
            <dt>{t("provider")}</dt>
            <dd>{view.provider || t("notSet")}</dd>
          </div>
          <div className="gh-kv">
            <dt>{t("webhookSecret")}</dt>
            <dd>{set(view.webhook_secret_configured)}</dd>
          </div>
          <div className="gh-kv">
            <dt>{t("apiKey")}</dt>
            <dd>{set(view.api_key_configured)}</dd>
          </div>
        </dl>
        <p className="gh-muted mt-3 text-xs">{t("chargingHelp")}</p>
      </Panel>
      <Panel id="plans-h" title={t("plansTitle")} intro={t("plansIntro")}>
        <ul className="divide-y divide-slate-200 dark:divide-navy-800">
          {view.plans.map((p) => (
            <li key={p.key} className="space-y-2 py-4 first:pt-0">
              <p className="font-semibold">{tp(p.key)}</p>
              <PlanEditor plan={p} label={tp(p.key)} />
            </li>
          ))}
        </ul>
      </Panel>
      <Panel id="assign-h" title={t("assignTitle")} intro={t("assignIntro")}>
        <AssignPlan />
      </Panel>
      <Panel id="subs-h" title={t("subsTitle")} bodyClassName="overflow-x-auto">
        {view.subscriptions.length === 0 ? (
          <p className="gh-muted px-5 py-4 text-sm">{t("noSubs")}</p>
        ) : (
          <table className="gh-table-admin">
            <caption className="sr-only">{t("subsTitle")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("email")}</th>
                <th scope="col">{t("planLabel")}</th>
                <th scope="col">{t("status")}</th>
                <th scope="col">{t("trialEnds")}</th>
                <th scope="col">{t("provider")}</th>
              </tr>
            </thead>
            <tbody>
              {view.subscriptions.map((s) => (
                <tr key={s.user_id}>
                  <th scope="row" className="text-sm font-normal">
                    {s.email}
                  </th>
                  <td className="text-sm">
                    {tp.has(s.effective_plan) ? tp(s.effective_plan) : s.effective_plan}
                  </td>
                  <td className="text-xs">{s.status}</td>
                  <td className="text-xs">{when(s.trial_ends_at)}</td>
                  <td className="text-xs">{s.provider ?? "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </>
  );
}
