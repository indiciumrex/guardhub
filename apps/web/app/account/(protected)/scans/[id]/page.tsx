/**
 * Full report of a saved scan: the same report component as the free scan; polls while
 * the scan is still running.
 */
import type { Metadata } from "next";
import Link from "next/link";
import { getLocale, getTranslations } from "next-intl/server";
import { ScanLive } from "@/components/scan/ScanLive";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import type { ScanView } from "@/lib/types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("scanLive");
  return { title: t("metaTitle") };
}

export default async function AccountScanPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const locale = await getLocale();
  const scan = await loadProtected(() =>
    serverApiFetch<ScanView>(`/scans/${encodeURIComponent(id)}`, { query: { locale } }),
  );
  const t = await getTranslations("project");
  return (
    <div className="max-w-4xl space-y-6">
      {scan.project_id ? (
        <Link href={`/account/projects/${scan.project_id}`} className="gh-link text-sm">
          {t("backToProject")}
        </Link>
      ) : null}
      <ScanLive key={`${scan.id}-${locale}`} scanId={scan.id} source="account" initial={scan} />
    </div>
  );
}
