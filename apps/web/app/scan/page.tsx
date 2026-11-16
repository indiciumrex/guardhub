import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { ScanFlow } from "@/components/scan/ScanFlow";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("scanFlow");
  return { title: t("metaTitle") };
}

export default async function ScanPage() {
  const t = await getTranslations("scanFlow");
  return (
    <div className="gh-container max-w-3xl py-12">
      <h1 className="text-3xl font-bold sm:text-4xl">{t("title")}</h1>
      <p className="gh-muted mt-3 text-lg">{t("intro")}</p>
      <ol className="mt-6 grid gap-3 text-sm sm:grid-cols-3">
        {(["step1", "step2", "step3"] as const).map((step, index) => (
          <li key={step} className="flex items-center gap-2">
            <span
              aria-hidden="true"
              className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-navy-900 text-xs font-bold text-white dark:bg-teal-300 dark:text-navy-950"
            >
              {index + 1}
            </span>
            <span>{t(`steps.${step}`)}</span>
          </li>
        ))}
      </ol>
      <div className="mt-8">
        <ScanFlow />
      </div>
      <p className="gh-muted mt-6 text-sm">{t("permissionNote")}</p>
    </div>
  );
}
