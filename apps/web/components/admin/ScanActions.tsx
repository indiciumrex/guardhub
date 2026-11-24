"use client";
/**
 * Cancel (queued/running) and run-again (a saved project's scan) for one scan. Cancelling asks
 * for a second click; both are audited by the API (scan.cancel / scan.rerun).
 */
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import type { AdminScan } from "@/lib/admin-types";
import { useErrorMessage } from "@/lib/use-error-message";

export function ScanActions({ scan }: { scan: AdminScan }) {
  const t = useTranslations("adminCenter.scans");
  const errorMessage = useErrorMessage();
  const router = useRouter();
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function act(action: "cancel" | "rerun") {
    setBusy(true);
    setError(null);
    try {
      const r = await apiFetch<AdminScan>(`/admin/scans/${scan.id}/${action}`, { method: "POST" });
      setNotice(action === "cancel" ? t("cancelled") : t("rerunStarted", { id: r.id }));
      setConfirming(false);
      router.refresh();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  if (!scan.can_cancel && !scan.can_rerun) return null;
  return (
    <div className="flex flex-col items-start gap-1 text-sm">
      <div className="flex flex-wrap gap-2">
        {scan.can_cancel && !confirming ? (
          <button
            type="button"
            className="gh-btn gh-btn-secondary min-h-9 px-3 py-1"
            disabled={busy}
            onClick={() => setConfirming(true)}
          >
            {t("cancel")}
          </button>
        ) : null}
        {scan.can_cancel && confirming ? (
          <>
            <button
              type="button"
              className="gh-btn gh-btn-primary min-h-9 px-3 py-1"
              disabled={busy}
              onClick={() => void act("cancel")}
            >
              {t("confirmCancel")}
            </button>
            <button
              type="button"
              className="gh-btn gh-btn-secondary min-h-9 px-3 py-1"
              disabled={busy}
              onClick={() => setConfirming(false)}
            >
              {t("keepRunning")}
            </button>
          </>
        ) : null}
        {scan.can_rerun ? (
          <button
            type="button"
            className="gh-btn gh-btn-secondary min-h-9 px-3 py-1"
            disabled={busy}
            onClick={() => void act("rerun")}
          >
            {t("rerun")}
          </button>
        ) : null}
      </div>
      {notice ? <p role="status">{notice}</p> : null}
      {error ? (
        <p role="alert" className="text-xs text-red-800 dark:text-red-200">
          {error}
        </p>
      ) : null}
    </div>
  );
}
