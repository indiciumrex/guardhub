"use client";
/**
 * Active testing on the customer's own site (Phase 5B, beta). Until every lock holds (the
 * founder's go, the final terms, approval, modules, kill switch, scanner, a verified site) it
 * only explains what is still missing; nothing can be started. SSRF has its own gate (a live
 * OOB collaborator): without it SSRF is not offered and the panel says it is not covered.
 * Once available: choose checks and excluded paths, accept exactly the current terms (by
 * version, linked, never paraphrased here), start, and a prominent "Stop now" while it runs.
 */
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { StatusBadge } from "@/components/admin/Stat";
import { apiFetch } from "@/lib/api";
import { useErrorMessage } from "@/lib/use-error-message";

export interface ActiveReadiness {
  available: boolean;
  blocked_by: string[];
  terms_version: string | null;
  checks: string[];
  running_scan_id: string | null;
  ssrf_covered: boolean;
}

function SsrfNotCovered() {
  const t = useTranslations("customerActive");
  return <p className="gh-muted text-xs">{t("ssrfNotCovered")}</p>;
}

export function CustomerActiveTesting({
  projectId,
  readiness,
}: {
  projectId: string;
  readiness: ActiveReadiness;
}) {
  const t = useTranslations("customerActive");
  const tChecks = useTranslations("checks");
  const errorMessage = useErrorMessage();
  const router = useRouter();
  const [checks, setChecks] = useState<string[]>(readiness.checks);
  const [exclude, setExclude] = useState("/admin");
  const [accepted, setAccepted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const base = `/projects/${encodeURIComponent(projectId)}/active`;

  async function call(path: string, body?: object) {
    setBusy(true);
    setError(null);
    try {
      await apiFetch(path, { method: "POST", body });
      router.refresh();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  if (readiness.running_scan_id) {
    return (
      <div className="gh-tone-crit space-y-2 rounded-lg border p-4" role="status">
        <p className="font-semibold">{t("running")}</p>
        <button
          type="button"
          className="gh-btn-primary"
          disabled={busy}
          onClick={() => void call(`${base}/scans/${readiness.running_scan_id}/stop`)}
        >
          {t("stop")}
        </button>
        <p className="text-xs">{t("stopHelp")}</p>
        {error ? <p role="alert">{error}</p> : null}
      </div>
    );
  }

  if (!readiness.available) {
    return (
      <div className="space-y-3">
        <StatusBadge tone="locked">{t("notAvailable")}</StatusBadge>
        <p className="text-sm">{t("notAvailableIntro")}</p>
        <ul aria-label={t("waitingFor")} className="list-disc space-y-1 pl-5 text-sm">
          {readiness.blocked_by.map((b) => (
            <li key={b}>{t(`lock.${b}`)}</li>
          ))}
        </ul>
        {readiness.ssrf_covered ? null : <SsrfNotCovered />}
      </div>
    );
  }

  return (
    <form
      aria-label={t("formLabel")}
      className="space-y-4 text-sm"
      onSubmit={(e) => {
        e.preventDefault();
        void call(`${base}/scans`, {
          checks,
          exclude: exclude
            .split(/[\n,]/)
            .map((p) => p.trim())
            .filter(Boolean),
          terms_version: readiness.terms_version,
          accept_terms: accepted,
        });
      }}
    >
      <fieldset>
        <legend className="font-medium">{t("checksLabel")}</legend>
        <div className="mt-1 flex flex-wrap gap-3">
          {readiness.checks.map((c) => (
            <label key={c} className="inline-flex min-h-9 items-center gap-2">
              <input
                type="checkbox"
                checked={checks.includes(c)}
                onChange={(e) =>
                  setChecks((cur) => (e.target.checked ? [...cur, c] : cur.filter((x) => x !== c)))
                }
                className="h-4 w-4"
              />
              {tChecks.has(`${c}.name`) ? tChecks(`${c}.name`) : c}
            </label>
          ))}
        </div>
        {readiness.ssrf_covered ? null : (
          <div className="mt-2">
            <SsrfNotCovered />
          </div>
        )}
      </fieldset>
      <div>
        <label htmlFor="active-exclude" className="block font-medium">
          {t("excludeLabel")}
        </label>
        <textarea
          id="active-exclude"
          value={exclude}
          rows={2}
          onChange={(e) => setExclude(e.target.value)}
          className="gh-input mt-1 w-full font-mono text-xs"
        />
        <p className="gh-muted mt-1 text-xs">{t("excludeHelp")}</p>
      </div>
      <label className="flex items-start gap-2">
        <input
          type="checkbox"
          checked={accepted}
          onChange={(e) => setAccepted(e.target.checked)}
          className="mt-1 h-4 w-4"
        />
        <span>
          {t("acceptTerms", { version: readiness.terms_version ?? "" })}{" "}
          <a
            href={`/legal/active-testing?v=${encodeURIComponent(readiness.terms_version ?? "")}`}
            className="gh-link"
            target="_blank"
            rel="noreferrer"
          >
            {t("readTerms")}
          </a>
        </span>
      </label>
      <button
        type="submit"
        className="gh-btn-primary"
        disabled={busy || !accepted || checks.length === 0}
      >
        {t("start")}
      </button>
      {error ? (
        <p role="alert" className="text-red-800 dark:text-red-200">
          {error}
        </p>
      ) : null}
    </form>
  );
}
