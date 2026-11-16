import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { ClaimScan } from "@/components/account/ClaimScan";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("claim");
  return { title: t("title") };
}

export default async function ClaimPage() {
  const t = await getTranslations("claim");
  return (
    <div className="max-w-2xl">
      <h1 className="text-3xl font-bold">{t("title")}</h1>
      <div className="mt-6">
        <ClaimScan />
      </div>
    </div>
  );
}
