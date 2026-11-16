/**
 * Landing page: value proposition (Enter → See → Fix), the six checks, the permission-first
 * promise, and a call to action to the free scan.
 */
import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { CHECK_IDS } from "@/lib/contract.gen";
import { ShieldMark } from "@/components/brand/ShieldMark";

const STEPS = ["enter", "see", "fix"] as const;
const PROMISES = ["permission", "passive", "privacy"] as const;

export default async function LandingPage() {
  const t = await getTranslations("landing");
  const tChecks = await getTranslations("checks");
  return (
    <>
      <section className="border-b border-slate-200 bg-white dark:border-navy-800 dark:bg-navy-900">
        <div className="gh-container grid items-center gap-10 py-16 sm:py-24 lg:grid-cols-[1.4fr_1fr]">
          <div>
            <p className="text-sm font-semibold uppercase tracking-wide text-teal-800 dark:text-teal-300">
              {t("eyebrow")}
            </p>
            <h1 className="mt-3 text-4xl font-bold tracking-tight sm:text-5xl">{t("title")}</h1>
            <p className="gh-muted mt-5 max-w-2xl text-lg leading-relaxed">{t("subtitle")}</p>
            <div className="mt-8 flex flex-wrap gap-3">
              <Link href="/scan" className="gh-btn-primary px-6 text-base">
                {t("cta")}
              </Link>
              <Link href="/account/register" className="gh-btn-secondary px-6 text-base">
                {t("secondaryCta")}
              </Link>
            </div>
            <p className="gh-muted mt-4 text-sm">{t("ctaNote")}</p>
          </div>
          <div className="hidden justify-center lg:flex">
            <ShieldMark className="h-56 w-56" />
          </div>
        </div>
      </section>

      <section aria-labelledby="how-heading" className="gh-container py-16">
        <h2 id="how-heading" className="text-2xl font-bold sm:text-3xl">
          {t("how.title")}
        </h2>
        <ol className="mt-8 grid gap-6 md:grid-cols-3">
          {STEPS.map((step, index) => (
            <li key={step} className="gh-card p-6">
              <span
                aria-hidden="true"
                className="flex h-10 w-10 items-center justify-center rounded-full bg-navy-900 font-bold text-white dark:bg-teal-300 dark:text-navy-950"
              >
                {index + 1}
              </span>
              <h3 className="mt-4 text-lg font-semibold">{t(`how.${step}.title`)}</h3>
              <p className="gh-muted mt-2 leading-relaxed">{t(`how.${step}.body`)}</p>
            </li>
          ))}
        </ol>
      </section>

      <section
        aria-labelledby="checks-heading"
        className="border-y border-slate-200 bg-white py-16 dark:border-navy-800 dark:bg-navy-900"
      >
        <div className="gh-container">
          <h2 id="checks-heading" className="text-2xl font-bold sm:text-3xl">
            {t("checks.title")}
          </h2>
          <p className="gh-muted mt-3 max-w-2xl">{t("checks.intro")}</p>
          <ul className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {CHECK_IDS.map((id) => (
              <li key={id} className="rounded-xl border border-slate-200 p-5 dark:border-navy-700">
                <h3 className="font-semibold">{tChecks(`${id}.name`)}</h3>
                <p className="gh-muted mt-2 text-sm leading-relaxed">
                  {tChecks(`${id}.description`)}
                </p>
              </li>
            ))}
          </ul>
        </div>
      </section>

      <section aria-labelledby="promise-heading" className="gh-container py-16">
        <h2 id="promise-heading" className="text-2xl font-bold sm:text-3xl">
          {t("promise.title")}
        </h2>
        <p className="gh-muted mt-3 max-w-2xl">{t("promise.intro")}</p>
        <ul className="mt-8 grid gap-6 md:grid-cols-3">
          {PROMISES.map((item) => (
            <li key={item} className="border-l-4 border-teal-600 pl-4 dark:border-teal-400">
              <h3 className="font-semibold">{t(`promise.${item}.title`)}</h3>
              <p className="gh-muted mt-2 text-sm leading-relaxed">{t(`promise.${item}.body`)}</p>
            </li>
          ))}
        </ul>
      </section>

      <section className="gh-container pb-4">
        <div className="rounded-2xl bg-navy-900 px-6 py-12 text-center text-white sm:px-12 dark:bg-navy-800">
          <h2 className="text-2xl font-bold sm:text-3xl">{t("final.title")}</h2>
          <p className="mx-auto mt-3 max-w-xl text-navy-100">{t("final.body")}</p>
          <Link
            href="/scan"
            className="gh-btn mt-8 bg-teal-300 px-6 text-base text-navy-950 hover:bg-teal-200"
          >
            {t("cta")}
          </Link>
        </div>
      </section>
    </>
  );
}
