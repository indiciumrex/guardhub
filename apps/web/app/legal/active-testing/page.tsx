/**
 * The published active-testing terms (final prompt item 6): exactly the text customers consent to,
 * served by the API only while its SHA-256 matches the configured one (apps/api/guardhub_api/legal.py).
 * The text is shown as it stands (no reformatting), with its version and fingerprint, so a customer
 * can check what they accepted. Until the founder publishes it, the page says so.
 */
import type { Metadata } from "next";
import { getLocale, getTranslations } from "next-intl/server";
import { ApiError } from "@/lib/api";
import { serverApiFetch } from "@/lib/api-server";

interface PublishedTerms {
  version: string;
  sha256: string;
  locale: "en" | "tr";
  text: string;
}

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("legalTerms");
  return { title: t("title") };
}

async function load(locale: string): Promise<PublishedTerms | null> {
  try {
    return await serverApiFetch<PublishedTerms>("/legal/active-testing", {
      query: { locale: locale === "tr" ? "tr" : "en" },
    });
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return null;
    throw err;
  }
}

export default async function ActiveTestingTermsPage() {
  const locale = await getLocale();
  const terms = await load(locale);
  const t = await getTranslations("legalTerms");
  return (
    <div className="gh-container max-w-3xl py-12">
      <h1 className="text-3xl font-bold">{t("title")}</h1>
      {terms ? (
        <>
          <dl className="gh-muted mt-3 space-y-1 text-sm">
            <div>
              <dt className="inline">{t("version")}: </dt>
              <dd className="inline font-mono">{terms.version}</dd>
            </div>
            <div>
              <dt className="inline">{t("fingerprint")}: </dt>
              <dd className="inline break-all font-mono text-xs">{terms.sha256}</dd>
            </div>
          </dl>
          {terms.locale !== locale && locale === "tr" ? (
            <p className="mt-3 text-sm">{t("englishOnly")}</p>
          ) : null}
          {terms.locale === "tr" ? <p className="mt-3 text-sm">{t("translationNote")}</p> : null}
          <div
            lang={terms.locale}
            className="gh-panel mt-6 whitespace-pre-wrap break-words p-6 text-sm leading-relaxed"
          >
            {terms.text}
          </div>
        </>
      ) : (
        <p className="mt-4">{t("notPublished")}</p>
      )}
    </div>
  );
}
