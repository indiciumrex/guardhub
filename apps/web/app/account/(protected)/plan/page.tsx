/**
 * The customer's plan (Phase 5C): the current plan and its limits with today's usage, the
 * public plans and a one-time trial. A checkout link appears only for plans the API offers one
 * for (charging live and a provider price set); otherwise nothing can be bought here.
 */
import type { Metadata } from "next";
import Link from "next/link";
import { getFormatter, getTranslations } from "next-intl/server";
import { PageHeader, Panel, Stat, StatusBadge } from "@/components/admin/Stat";
import { StartTrial } from "@/components/customer/BillingControls";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import type { BillingView } from "@/lib/admin-types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("billing");
  return { title: t("title") };
}

export default async function PlanPage({
  searchParams,
}: {
  searchParams: Promise<{ checkout?: string }>;
}) {
  const { checkout } = await searchParams;
  const billing = await loadProtected(() => serverApiFetch<BillingView>("/billing"));
  const t = await getTranslations("billing");
  const tp = await getTranslations("billing.plan");
  const tc = await getTranslations("customer");
  const format = await getFormatter();
  const when = (v: string | null) =>
    v ? format.dateTime(new Date(v), { dateStyle: "medium", timeZone: "UTC" }) : "-";
  const current = billing.limits;
  return (
    <>
      <PageHeader eyebrow={tc("eyebrow")} title={t("title")} intro={t("intro")} />
      {checkout === "done" || checkout === "cancelled" ? (
        <p role="status" className="gh-panel px-5 py-3 text-sm">
          {checkout === "done" ? t("checkoutDone") : t("checkoutCancelled")}
        </p>
      ) : null}
      <Panel
        id="current-h"
        title={t("current", { plan: tp(billing.plan) })}
        actions={
          billing.status === "trialing" ? (
            <StatusBadge tone="info">
              {t("trialUntil", { when: when(billing.trial_ends_at) })}
            </StatusBadge>
          ) : (
            <StatusBadge tone="ok">{t("active")}</StatusBadge>
          )
        }
      >
        <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3">
          <Stat label={t("sites")} value={`${billing.usage.sites} / ${current.max_sites}`} />
          <Stat
            label={t("scansToday")}
            value={`${billing.usage.scans_today} / ${current.scans_per_day}`}
          />
          <Stat label={t("concurrent")} value={current.concurrent_scans} />
        </dl>
      </Panel>
      <Panel id="plans-h" title={t("plansTitle")} bodyClassName="overflow-x-auto">
        <table className="gh-table-admin">
          <caption className="sr-only">{t("plansTitle")}</caption>
          <thead>
            <tr>
              <th scope="col">{t("colPlan")}</th>
              <th scope="col">{t("sites")}</th>
              <th scope="col">{t("scansPerDay")}</th>
              <th scope="col">{t("concurrent")}</th>
              <th scope="col">
                <span className="sr-only">{t("colAction")}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {billing.plans.map((p) => (
              <tr key={p.key}>
                <th scope="row" className="text-sm font-semibold">
                  {tp(p.key)}
                  {p.key === billing.plan ? (
                    <span className="ml-2">
                      <StatusBadge tone="ok">{t("yourPlan")}</StatusBadge>
                    </span>
                  ) : null}
                </th>
                <td className="tabular-nums">{p.max_sites}</td>
                <td className="tabular-nums">{p.scans_per_day}</td>
                <td className="tabular-nums">{p.concurrent_scans}</td>
                <td>
                  {billing.trial_available && p.trial_days > 0 && p.rank > current.rank ? (
                    <StartTrial plan={p.key} days={p.trial_days} label={tp(p.key)} />
                  ) : null}
                  {billing.checkout_plans.includes(p.key) ? (
                    <Link
                      href={`/account/plan/checkout?plan=${p.key}`}
                      className="gh-btn-secondary mt-1 min-h-9 px-3 py-1.5 text-sm"
                      aria-label={t("upgradeNamed", { plan: tp(p.key) })}
                    >
                      {t("upgrade")}
                    </Link>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="gh-muted px-5 py-3 text-xs">
          {billing.charging_live ? t("chargingLive") : t("chargingOff")}
        </p>
      </Panel>
    </>
  );
}
