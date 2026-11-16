"use client";
/**
 * Free scan flow (ADR-0001): enter a URL → prove ownership → "Verify & start scan".
 * On success the scan access token goes to sessionStorage and we open the progress page.
 */
import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { useFormatter, useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import { scanTokenKey } from "@/lib/navigation";
import type { Challenge, ChallengeScanResponse } from "@/lib/types";
import { useErrorMessage } from "@/lib/use-error-message";
import { Alert } from "@/components/ui/Alert";
import { OwnershipInstructions } from "./OwnershipInstructions";

export function ScanFlow() {
  const t = useTranslations("scanFlow");
  const tCommon = useTranslations("common");
  const format = useFormatter();
  const router = useRouter();
  const errorMessage = useErrorMessage();
  const [target, setTarget] = useState("");
  const [challenge, setChallenge] = useState<Challenge | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function requestChallenge(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const created = await apiFetch<Challenge>("/public/challenges", {
        method: "POST",
        body: { target_url: target.trim() },
      });
      setChallenge(created);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  async function verifyAndScan() {
    if (!challenge) return;
    setError(null);
    setBusy(true);
    try {
      const started = await apiFetch<ChallengeScanResponse>(
        `/public/challenges/${encodeURIComponent(challenge.challenge_id)}/scan`,
        { method: "POST" },
      );
      try {
        window.sessionStorage.setItem(scanTokenKey(started.scan_id), started.access_token);
      } catch {
        // Storage blocked: the progress page will explain that the report can't be opened.
      }
      router.push(`/scan/${encodeURIComponent(started.scan_id)}`);
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  }

  function startOver() {
    setChallenge(null);
    setError(null);
  }

  if (!challenge) {
    return (
      <form onSubmit={requestChallenge} className="gh-card space-y-4 p-6 sm:p-8" noValidate={false}>
        <div>
          <label htmlFor="target" className="gh-label">
            {t("urlLabel")}
          </label>
          <input
            id="target"
            name="target"
            type="text"
            inputMode="url"
            autoComplete="url"
            spellCheck={false}
            required
            maxLength={2048}
            placeholder={t("urlPlaceholder")}
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            aria-describedby="target-hint"
            className="gh-input"
          />
          <p id="target-hint" className="gh-muted mt-1 text-sm">
            {t("urlHint")}
          </p>
        </div>
        {error ? (
          <Alert tone="error" label={tCommon("errorLabel")}>
            {errorMessage(error)}
          </Alert>
        ) : null}
        <button type="submit" className="gh-btn-primary" disabled={busy || !target.trim()}>
          {busy ? tCommon("working") : t("continue")}
        </button>
      </form>
    );
  }

  return (
    <div className="space-y-6">
      <div className="gh-card p-6">
        <h2 className="text-xl font-semibold">
          {t("proveTitle", { origin: challenge.target_origin })}
        </h2>
        <p className="gh-muted mt-2 text-sm">
          {t("expires", {
            date: format.dateTime(new Date(challenge.expires_at), {
              dateStyle: "medium",
              timeStyle: "short",
              timeZone: "UTC",
            }),
          })}
        </p>
      </div>
      <OwnershipInstructions token={challenge.token} instructions={challenge.instructions} />
      {error ? (
        <Alert tone="error" label={tCommon("errorLabel")}>
          {errorMessage(error)}
        </Alert>
      ) : null}
      <div className="flex flex-wrap gap-3">
        <button type="button" className="gh-btn-primary" onClick={verifyAndScan} disabled={busy}>
          {busy ? t("verifying") : t("verifyAndScan")}
        </button>
        <button type="button" className="gh-btn-secondary" onClick={startOver} disabled={busy}>
          {t("startOver")}
        </button>
      </div>
      <p className="gh-muted text-sm">{t("dnsDelayHint")}</p>
    </div>
  );
}
