"use client";
/**
 * Project actions: "Verify" ownership and "Rescan" (needs a verified project).
 */
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import type { Project, ScanSummary } from "@/lib/types";
import { useErrorMessage } from "@/lib/use-error-message";
import { Alert } from "@/components/ui/Alert";

export function VerifyProjectButton({ projectId }: { projectId: string }) {
  const t = useTranslations("project");
  const tCommon = useTranslations("common");
  const router = useRouter();
  const errorMessage = useErrorMessage();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function verify() {
    setBusy(true);
    setError(null);
    try {
      await apiFetch<Project>(`/projects/${encodeURIComponent(projectId)}/verify`, {
        method: "POST",
      });
      router.refresh();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-3">
      <button type="button" onClick={verify} disabled={busy} className="gh-btn-primary">
        {busy ? t("verifying") : t("verify")}
      </button>
      {error ? (
        <Alert tone="error" label={tCommon("errorLabel")}>
          {errorMessage(error)}
        </Alert>
      ) : null}
    </div>
  );
}

export function RescanButton({ projectId, disabled }: { projectId: string; disabled?: boolean }) {
  const t = useTranslations("project");
  const tCommon = useTranslations("common");
  const router = useRouter();
  const errorMessage = useErrorMessage();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function rescan() {
    setBusy(true);
    setError(null);
    try {
      const scan = await apiFetch<ScanSummary>(`/projects/${encodeURIComponent(projectId)}/scans`, {
        method: "POST",
      });
      router.push(`/account/scans/${encodeURIComponent(scan.id)}`);
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  }

  return (
    <div className="space-y-3">
      <button type="button" onClick={rescan} disabled={busy || disabled} className="gh-btn-primary">
        {busy ? tCommon("working") : t("rescan")}
      </button>
      {error ? (
        <Alert tone="error" label={tCommon("errorLabel")}>
          {errorMessage(error)}
        </Alert>
      ) : null}
    </div>
  );
}
