"use client";
/**
 * Admin trusted domains (ADR-0003, docs/architecture.md §8.5): add a host, prove it once with
 * the usual ownership methods, then "Scan now" without the proof prompt while the proof stays
 * published. Exact host only. Removing asks for an in-page confirmation (no browser dialog).
 */
import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { useFormatter, useTranslations } from "next-intl";
import { OwnershipInstructions } from "@/components/scan/OwnershipInstructions";
import { Alert } from "@/components/ui/Alert";
import { apiFetch } from "@/lib/api";
import type { ScanSummary, TrustedDomain, TrustedDomainStatus } from "@/lib/types";
import { useErrorMessage } from "@/lib/use-error-message";

const API = "/admin/trusted-domains";

const chipClasses: Record<TrustedDomainStatus, string> = {
  pending: "border-amber-300 text-amber-900 dark:border-amber-700 dark:text-amber-100",
  active: "border-emerald-300 text-emerald-800 dark:border-emerald-700 dark:text-emerald-200",
  suspended: "border-red-300 text-red-800 dark:border-red-700 dark:text-red-200",
  revoked: "border-slate-300 text-slate-700 dark:border-slate-600 dark:text-slate-200",
};

/** Status as a text chip (colour is only a secondary cue). */
export function TrustedDomainStatusChip({ status }: { status: TrustedDomainStatus }) {
  const t = useTranslations("trustedDomains");
  return (
    <span
      className={`inline-flex rounded-full border px-2.5 py-0.5 text-xs font-semibold ${chipClasses[status]}`}
    >
      {t(`status.${status}`)}
    </span>
  );
}

export function AddTrustedDomainForm() {
  const t = useTranslations("trustedDomains");
  const tCommon = useTranslations("common");
  const router = useRouter();
  const errorMessage = useErrorMessage();
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await apiFetch<TrustedDomain>(API, { method: "POST", body: { target_url: target.trim() } });
      setTarget("");
      router.refresh();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="gh-panel space-y-4 px-5 py-4">
      <div>
        <label htmlFor="trusted-domain-url" className="gh-label">
          {t("addLabel")}
        </label>
        <p id="trusted-domain-hint" className="gh-muted mb-2 text-sm">
          {t("addHint")}
        </p>
        <input
          id="trusted-domain-url"
          type="text"
          inputMode="url"
          spellCheck={false}
          required
          maxLength={2048}
          placeholder="example.com"
          aria-describedby="trusted-domain-hint"
          value={target}
          onChange={(event) => setTarget(event.target.value)}
          className="gh-input"
        />
      </div>
      {error ? (
        <Alert tone="error" label={tCommon("errorLabel")}>
          {errorMessage(error)}
        </Alert>
      ) : null}
      <button type="submit" className="gh-btn-primary" disabled={busy}>
        {busy ? tCommon("working") : t("addSubmit")}
      </button>
    </form>
  );
}

type Action = "verify" | "scan" | "remove";

export function TrustedDomainCard({ domain }: { domain: TrustedDomain }) {
  const t = useTranslations("trustedDomains");
  const tCommon = useTranslations("common");
  const format = useFormatter();
  const router = useRouter();
  const errorMessage = useErrorMessage();
  const [busy, setBusy] = useState<Action | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const path = `${API}/${encodeURIComponent(domain.id)}`;
  const formatDate = (value: string) =>
    format.dateTime(new Date(value), { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" });

  async function run(action: Action, call: () => Promise<void>) {
    setBusy(action);
    setError(null);
    try {
      await call();
    } catch (err) {
      setError(err);
      setBusy(null);
      return;
    }
    if (action !== "scan") setBusy(null); // a scan navigates away; keep the button busy
  }

  const verify = () =>
    run("verify", async () => {
      await apiFetch<TrustedDomain>(`${path}/verify`, { method: "POST" });
      router.refresh();
    });
  const scan = () =>
    run("scan", async () => {
      const started = await apiFetch<ScanSummary>(`${path}/scan`, { method: "POST" });
      router.push(`/account/scans/${encodeURIComponent(started.id)}`);
    });
  const remove = () =>
    run("remove", async () => {
      await apiFetch<void>(path, { method: "DELETE" });
      setConfirming(false);
      router.refresh();
    });

  const headingId = `trusted-domain-${domain.id}`;
  return (
    <li className="gh-panel space-y-4 px-5 py-4" aria-labelledby={headingId}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 id={headingId} className="text-lg font-semibold break-all">
            {domain.host}
          </h3>
          <p className="gh-muted text-sm break-all">{domain.target_origin}</p>
        </div>
        <TrustedDomainStatusChip status={domain.status} />
      </div>

      <p className="text-sm">{t(`statusHelp.${domain.status}`)}</p>

      <dl className="gh-muted grid gap-1 text-sm sm:grid-cols-2">
        <div>
          <dt className="inline font-semibold">{t("provenAt")}: </dt>
          <dd className="inline">
            {domain.verified_at ? formatDate(domain.verified_at) : t("notYet")}
            {domain.method ? ` (${t(`method.${domain.method}`)})` : null}
          </dd>
        </div>
        <div>
          <dt className="inline font-semibold">{t("lastCheckedAt")}: </dt>
          <dd className="inline">
            {domain.last_checked_at ? formatDate(domain.last_checked_at) : t("notYet")}
          </dd>
        </div>
      </dl>

      {domain.status === "pending" ? (
        <section aria-label={t("instructionsHeading", { host: domain.host })}>
          <h4 className="mb-2 font-semibold">{t("instructionsHeading", { host: domain.host })}</h4>
          <OwnershipInstructions
            token={domain.verification.token}
            instructions={domain.verification}
          />
        </section>
      ) : null}
      {domain.status === "suspended" ? (
        <details>
          <summary className="gh-link cursor-pointer text-sm">{t("showInstructions")}</summary>
          <div className="mt-3">
            <OwnershipInstructions
              token={domain.verification.token}
              instructions={domain.verification}
            />
          </div>
        </details>
      ) : null}

      <div
        className="flex flex-wrap gap-3"
        role="group"
        aria-label={t("actionsLabel", { host: domain.host })}
      >
        <button
          type="button"
          onClick={verify}
          disabled={busy !== null}
          className={domain.status === "active" ? "gh-btn-secondary" : "gh-btn-primary"}
        >
          {busy === "verify"
            ? t("verifying")
            : domain.status === "pending"
              ? t("verify")
              : t("checkAgain")}
        </button>
        {domain.status === "active" ? (
          <button type="button" onClick={scan} disabled={busy !== null} className="gh-btn-primary">
            {busy === "scan" ? tCommon("working") : t("scanNow")}
          </button>
        ) : null}
        {!confirming ? (
          <button
            type="button"
            onClick={() => setConfirming(true)}
            disabled={busy !== null}
            className="gh-btn-secondary text-red-800 dark:text-red-200"
          >
            {t("remove")}
          </button>
        ) : null}
      </div>

      {confirming ? (
        <div
          role="group"
          aria-label={t("confirmLabel")}
          className="space-y-3 rounded-lg border border-red-300 p-4 dark:border-red-800"
        >
          <p className="text-sm">{t("confirmRemove", { host: domain.host })}</p>
          <div className="flex flex-wrap gap-3">
            <button
              type="button"
              onClick={remove}
              disabled={busy !== null}
              className="gh-btn bg-red-700 text-white hover:bg-red-800 dark:bg-red-300 dark:text-navy-950 dark:hover:bg-red-200"
            >
              {busy === "remove" ? tCommon("working") : t("confirmYes")}
            </button>
            <button
              type="button"
              onClick={() => setConfirming(false)}
              disabled={busy !== null}
              className="gh-btn-secondary"
            >
              {t("cancel")}
            </button>
          </div>
        </div>
      ) : null}

      {error ? (
        <Alert tone="error" label={tCommon("errorLabel")}>
          {errorMessage(error)}
        </Alert>
      ) : null}
    </li>
  );
}

export function TrustedDomainList({ domains }: { domains: TrustedDomain[] }) {
  const t = useTranslations("trustedDomains");
  if (domains.length === 0) return <p className="gh-muted">{t("empty")}</p>;
  return (
    <ul className="space-y-4">
      {domains.map((domain) => (
        <TrustedDomainCard key={domain.id} domain={domain} />
      ))}
    </ul>
  );
}
