/**
 * Service notice (server component): shown on every page while an admin has switched on
 * maintenance mode (GET /platform/status, no auth). It fails soft: if the status cannot be read,
 * nothing is shown and the API still refuses new scans on its own.
 */
import { getTranslations } from "next-intl/server";
import { serverApiFetch } from "@/lib/api-server";

interface PlatformStatus {
  maintenance: boolean;
  message: string;
}

export async function PlatformBanner() {
  let status: PlatformStatus | null = null;
  try {
    status = await serverApiFetch<PlatformStatus>("/platform/status");
  } catch {
    return null;
  }
  if (!status?.maintenance) return null;
  const t = await getTranslations("platformBanner");
  return (
    <div
      role="status"
      aria-label={t("label")}
      className="border-b border-amber-300 bg-amber-50 px-4 py-2 text-center text-sm font-medium text-amber-950 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-100"
    >
      {t("maintenance")}
      {status.message ? <span className="ml-1">{status.message}</span> : null}
    </div>
  );
}
