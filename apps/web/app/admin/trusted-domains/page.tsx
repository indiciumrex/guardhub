/**
 * Admin trusted domains (ADR-0003): the admin's own proven hosts. The admin layout already
 * requires role `admin` + full MFA; the API re-checks both and scopes rows to this admin.
 */
import type { Metadata } from "next";
import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { AddTrustedDomainForm, TrustedDomainList } from "@/components/admin/TrustedDomains";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import type { TrustedDomain } from "@/lib/types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("trustedDomains");
  return { title: t("title") };
}

export default async function TrustedDomainsPage() {
  const domains = await loadProtected(() =>
    serverApiFetch<TrustedDomain[]>("/admin/trusted-domains"),
  );
  const t = await getTranslations("trustedDomains");

  return (
    <div className="space-y-10">
      <div>
        <Link href="/admin" className="gh-link text-sm">
          {t("back")}
        </Link>
        <h1 className="mt-2 text-3xl font-bold">{t("title")}</h1>
        <p className="gh-muted mt-2 max-w-2xl">{t("intro")}</p>
      </div>

      <section aria-labelledby="rules-heading" className="gh-card max-w-2xl p-5">
        <h2 id="rules-heading" className="text-lg font-semibold">
          {t("rulesHeading")}
        </h2>
        <ul className="mt-3 list-disc space-y-2 pl-5 text-sm">
          <li>{t("ruleOnce")}</li>
          <li>{t("ruleKeep")}</li>
          <li>{t("ruleExact")}</li>
          <li>{t("ruleOthers")}</li>
        </ul>
      </section>

      <section aria-labelledby="add-heading" className="max-w-2xl space-y-4">
        <h2 id="add-heading" className="text-xl font-semibold">
          {t("addHeading")}
        </h2>
        <AddTrustedDomainForm />
      </section>

      <section aria-labelledby="list-heading" className="space-y-4">
        <h2 id="list-heading" className="text-xl font-semibold">
          {t("listHeading")}
        </h2>
        <TrustedDomainList domains={domains} />
      </section>
    </div>
  );
}
