"use client";
/**
 * "Scan now" for one verified site (New scan hub). The API decides: ownership is proven again
 * when stale (§9.2), plan limits apply, a running scan blocks a second one. On success the
 * report page opens and follows the scan live.
 */
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import type { ScanSummary } from "@/lib/types";
import { useErrorMessage } from "@/lib/use-error-message";

export function ScanNowButton({ path, label }: { path: string; label: string }) {
  const t = useTranslations("newScan");
  const errorMessage = useErrorMessage();
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <div className="flex flex-col items-end gap-1">
      <button
        type="button"
        className="gh-btn-primary min-h-10 px-3 py-1.5"
        disabled={busy}
        aria-label={label}
        onClick={async () => {
          setBusy(true);
          setError(null);
          try {
            const scan = await apiFetch<ScanSummary>(path, { method: "POST" });
            router.push(`/account/scans/${scan.id}`);
          } catch (err) {
            setError(errorMessage(err));
            setBusy(false);
          }
        }}
      >
        {busy ? t("starting") : t("scanNow")}
      </button>
      {error ? (
        <p role="alert" className="max-w-xs text-right text-xs text-red-800 dark:text-red-200">
          {error}
        </p>
      ) : null}
    </div>
  );
}
