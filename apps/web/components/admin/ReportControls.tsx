"use client";
/**
 * Reports (Prompt 2 §3): the print / save-as-PDF button and the scheduled summary switches.
 * PDF comes from the browser's print dialog on a print-friendly page (no server PDF engine).
 */
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import type { ReportSchedule } from "@/lib/admin-types";
import { useErrorMessage } from "@/lib/use-error-message";

export function PrintReport() {
  const t = useTranslations("adminCenter.reports");
  return (
    <button
      type="button"
      className="gh-btn-secondary min-h-9 px-3 py-1.5 text-sm"
      onClick={() => window.print()}
    >
      {t("printPdf")}
    </button>
  );
}

export function ReportScheduleSwitch({
  schedule,
  label,
}: {
  schedule: ReportSchedule;
  label: string;
}) {
  const errorMessage = useErrorMessage();
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <div className="space-y-1">
      <label className="inline-flex min-h-11 items-center gap-3 text-sm font-medium">
        <input
          type="checkbox"
          role="switch"
          aria-checked={schedule.enabled}
          checked={schedule.enabled}
          disabled={busy}
          className="h-5 w-5"
          onChange={async (e) => {
            setBusy(true);
            setError(null);
            try {
              await apiFetch(`/admin/report-schedules/${schedule.frequency}`, {
                method: "PUT",
                body: { enabled: e.target.checked },
              });
              router.refresh();
            } catch (err) {
              setError(errorMessage(err));
            } finally {
              setBusy(false);
            }
          }}
        />
        {label}
      </label>
      {error ? (
        <p role="alert" className="text-xs text-red-800 dark:text-red-200">
          {error}
        </p>
      ) : null}
    </div>
  );
}
