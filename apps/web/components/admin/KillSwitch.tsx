"use client";
/**
 * The active-test kill switch (POST /admin/active/kill, ADR-0008 §3): stop every active scan, or
 * one scan by id. Stopping takes effect immediately; releasing needs a second, explicit click.
 * Every change is audited (active.kill / active.unkill).
 */
import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import type { KillState } from "@/lib/admin-types";
import { useErrorMessage } from "@/lib/use-error-message";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function KillSwitch({ engaged }: { engaged: boolean }) {
  const t = useTranslations("adminCenter.kill");
  const errorMessage = useErrorMessage();
  const router = useRouter();
  const [state, setState] = useState(engaged);
  const [confirmRelease, setConfirmRelease] = useState(false);
  const [scanId, setScanId] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function send(nextEngaged: boolean, scan?: string) {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const r = await apiFetch<KillState>("/admin/active/kill", {
        method: "POST",
        body: { engaged: nextEngaged, scan_id: scan ?? null },
      });
      if (scan) {
        setMessage(t("scanStopped", { id: scan }));
        setScanId("");
      } else {
        setState(r.engaged);
      }
      setConfirmRelease(false);
      router.refresh();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  function stopOne(e: FormEvent) {
    e.preventDefault();
    const id = scanId.trim();
    if (!UUID.test(id)) {
      setError(t("invalidId"));
      return;
    }
    void send(true, id);
  }

  return (
    <div className="space-y-4 text-sm">
      <p>
        <span className="font-semibold">{t("globalLabel")}: </span>
        {state ? t("engaged") : t("released")}
      </p>
      <div className="flex flex-wrap gap-2">
        {!state ? (
          <button
            type="button"
            className="gh-btn gh-btn-primary"
            disabled={busy}
            onClick={() => void send(true)}
          >
            {t("stopAll")}
          </button>
        ) : confirmRelease ? (
          <>
            <button
              type="button"
              className="gh-btn gh-btn-primary"
              disabled={busy}
              onClick={() => void send(false)}
            >
              {t("confirmRelease")}
            </button>
            <button
              type="button"
              className="gh-btn gh-btn-secondary"
              disabled={busy}
              onClick={() => setConfirmRelease(false)}
            >
              {t("keep")}
            </button>
          </>
        ) : (
          <button
            type="button"
            className="gh-btn gh-btn-secondary"
            disabled={busy}
            onClick={() => setConfirmRelease(true)}
          >
            {t("release")}
          </button>
        )}
      </div>
      <form onSubmit={stopOne} className="flex flex-wrap items-end gap-2">
        <div>
          <label htmlFor="kill-scan-id" className="gh-label">
            {t("scanIdLabel")}
          </label>
          <input
            id="kill-scan-id"
            value={scanId}
            onChange={(e) => setScanId(e.target.value)}
            className="gh-input w-80 max-w-full font-mono"
            autoComplete="off"
            spellCheck={false}
          />
        </div>
        <button type="submit" className="gh-btn gh-btn-secondary" disabled={busy || !scanId}>
          {t("stopOne")}
        </button>
      </form>
      {message ? <p role="status">{message}</p> : null}
      {error ? (
        <p role="alert" className="text-red-800 dark:text-red-200">
          {error}
        </p>
      ) : null}
    </div>
  );
}
