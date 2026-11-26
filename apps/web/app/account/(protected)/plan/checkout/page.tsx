/**
 * Checkout (final prompt item 7), inert until the founder switches charging on: the plan's limits
 * and a button that opens the payment provider's own page. No price is shown or stored here; the
 * provider's page shows it. While charging is off (or the plan has no provider price) the page
 * only explains that payments are not switched on: there is no button, and the API refuses too.
 */
import type { Metadata } from "next";
import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { PageHeader, Panel, Stat, StatusBadge } from "@/components/admin/Stat";
import { StartCheckout } from "@/components/customer/BillingControls";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import type { BillingView } from "@/lib/admin-types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("checkout");
  return { title: t("title") };
}

export default async function CheckoutPage({
  searchParams,
}: {
  searchParams: Promise<{ plan?: string }>;
}) {
  const { plan: wanted } = await searchParams;
  const billing = await loadProtected(() => serverApiFetch<BillingView>("/billing"));
  const t = await getTranslations("checkout");
  const tb = await getTranslations("billing");
  const tp = await getTranslations("billing.plan");
  const plan = billing.plans.find((p) => p.key === wanted);
  const open = plan !== undefined && billing.checkout_plans.includes(plan.key);
  return (
    <>
      <PageHeader eyebrow={tb("title")} title={t("title")} intro={t("intro")} />
      {plan ? (
        <Panel id="plan-h" title={t("planTitle", { plan: tp(plan.key) })}>
          <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            <Stat label={tb("sites")} value={plan.max_sites} />
            <Stat label={tb("scansPerDay")} value={plan.scans_per_day} />
            <Stat label={tb("concurrent")} value={plan.concurrent_scans} />
          </dl>
        </Panel>
      ) : null}
      <Panel id="pay-h" title={t("payTitle")} emphasis={open ? undefined : "warn"}>
        {open && plan ? (
          <div className="space-y-3 text-sm">
            <p>{t("providerNote")}</p>
            <StartCheckout plan={plan.key} label={tp(plan.key)} />
          </div>
        ) : (
          <div className="space-y-3 text-sm">
            <StatusBadge tone="locked">{t("off")}</StatusBadge>
            <p>{t("offHelp")}</p>
          </div>
        )}
        <p className="mt-4 text-sm">
          <Link href="/account/plan" className="gh-link">
            {t("back")}
          </Link>
        </p>
      </Panel>
    </>
  );
}
