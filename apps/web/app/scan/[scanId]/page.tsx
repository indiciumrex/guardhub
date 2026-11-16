import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { PublicScanView } from "@/components/scan/PublicScanView";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("scanLive");
  return { title: t("metaTitle"), robots: { index: false, follow: false } };
}

export default async function ScanProgressPage({
  params,
}: {
  params: Promise<{ scanId: string }>;
}) {
  const { scanId } = await params;
  return (
    <div className="gh-container max-w-4xl py-12">
      <PublicScanView scanId={scanId} />
    </div>
  );
}
