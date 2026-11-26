/**
 * Verified sites (profile prompt, item 2): one list of every site this admin has proven (trusted
 * domains and their own website projects) with one status each. The admin layout requires role
 * admin + full MFA; the API re-checks both and returns only this admin's own rows.
 */
import type { Metadata } from "next";
import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { PageHeader, Panel, Stat } from "@/components/admin/Stat";
import { VerifiedSitesTable } from "@/components/admin/VerifiedSites";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import type { SiteRow } from "@/lib/admin-types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("sites");
  return { title: t("title") };
}

export default async function VerifiedSitesPage() {
  const sites = await loadProtected(() => serverApiFetch<SiteRow[]>("/admin/sites"));
  const t = await getTranslations("sites");
  const tConsole = await getTranslations("adminCenter.console");
  const count = (s: SiteRow["status"]) => sites.filter((r) => r.status === s).length;
  return (
    <>
      <PageHeader
        eyebrow={tConsole("eyebrow")}
        title={t("title")}
        intro={t("intro")}
        actions={
          <Link href="/admin/trusted-domains" className="gh-btn-secondary">
            {t("addDomain")}
          </Link>
        }
      />
      <dl aria-label={t("summary")} className="grid gap-4 sm:grid-cols-4">
        <Stat label={t("status.verified")} value={count("verified")} tone="ok" />
        <Stat
          label={t("status.expired")}
          value={count("expired")}
          tone={count("expired") ? "warn" : "neutral"}
        />
        <Stat
          label={t("status.failed")}
          value={count("failed")}
          tone={count("failed") ? "crit" : "neutral"}
        />
        <Stat label={t("status.pending")} value={count("pending")} tone="neutral" />
      </dl>
      <Panel id="sites-h" title={t("listTitle")} intro={t("listIntro")}>
        <VerifiedSitesTable sites={sites} />
      </Panel>
      <Panel id="rules-h" title={t("rulesTitle")} emphasis="locked">
        <ul className="list-disc space-y-1 pl-5 text-sm">
          <li>{t("ruleVerified")}</li>
          <li>{t("ruleExpired")}</li>
          <li>{t("ruleFailed")}</li>
          <li>{t("ruleScan")}</li>
        </ul>
      </Panel>
    </>
  );
}
