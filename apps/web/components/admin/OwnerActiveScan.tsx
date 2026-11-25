"use client";
/**
 * Owner-target active scan (POST /admin/active/owner-scan, ADR-0008 §8): active checks on a
 * domain GuardHub owns (an active admin trusted domain). The form shows every lock that still
 * blocks it and stays disabled until none does; the API checks each lock again. Never a customer
 * target. SSRF stays unavailable until the OOB collaborator exists.
 */
import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import type { OwnerScanReadiness, OwnerScanStarted } from "@/lib/admin-types";
import { useErrorMessage } from "@/lib/use-error-message";

const CHECKS = [
  "active_xss",
  "active_sqli",
  "active_redirect",
  "active_cors",
  "active_idor",
  "active_ssrf",
];
const DEFAULT_EXCLUDE = "/admin\n/api";

export function OwnerActiveScan({ readiness }: { readiness: OwnerScanReadiness }) {
  const t = useTranslations("adminCenter.ownerScan");
  const errorMessage = useErrorMessage();
  const router = useRouter();
  const r = readiness;
  const usable = (c: string) =>
    r.modules_on.includes(c) && (c !== "active_ssrf" || r.oob_configured);
  const [target, setTarget] = useState(r.targets[0]?.id ?? "");
  const [checks, setChecks] = useState<string[]>(CHECKS.filter(usable));
  const [exclude, setExclude] = useState(DEFAULT_EXCLUDE);
  const [accounts, setAccounts] = useState({ ca: "", ma: "", cb: "", mb: "" });
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [started, setStarted] = useState<OwnerScanStarted | null>(null);
  const [error, setError] = useState<string | null>(null);
  const blocked = r.blocked_by.length > 0;
  const idor = checks.includes("active_idor");

  function toggle(c: string) {
    setChecks((cur) => (cur.includes(c) ? cur.filter((x) => x !== c) : [...cur, c]));
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setStarted(null);
    const withAccounts = idor && accounts.ca && accounts.cb;
    try {
      const res = await apiFetch<OwnerScanStarted>("/admin/active/owner-scan", {
        method: "POST",
        body: {
          trusted_domain_id: target,
          checks,
          exclude: exclude
            .split("\n")
            .map((p) => p.trim())
            .filter(Boolean),
          account_a: withAccounts ? { cookie: accounts.ca, marker: accounts.ma } : null,
          account_b: withAccounts ? { cookie: accounts.cb, marker: accounts.mb } : null,
        },
      });
      setStarted(res);
      setConfirmed(false);
      setAccounts({ ca: "", ma: "", cb: "", mb: "" });
      router.refresh();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4 text-sm">
      {blocked ? (
        <div role="status" className="gh-tone-locked rounded-lg border p-3">
          <p className="font-semibold">{t("blockedTitle")}</p>
          <ul className="mt-1 list-disc pl-5">
            {r.blocked_by.map((lock) => (
              <li key={lock}>{t(`lock.${lock}`)}</li>
            ))}
          </ul>
        </div>
      ) : (
        <p role="status" className="font-semibold">
          {t("ready")}
        </p>
      )}
      <form onSubmit={submit} className="space-y-4">
        <div>
          <label htmlFor="owner-target" className="gh-label">
            {t("target")}
          </label>
          {r.targets.length ? (
            <select
              id="owner-target"
              className="gh-input w-80 max-w-full"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            >
              {r.targets.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.origin}
                </option>
              ))}
            </select>
          ) : (
            <p className="gh-muted">{t("noTargets")}</p>
          )}
        </div>
        <fieldset>
          <legend className="gh-label">{t("checks")}</legend>
          <div className="flex flex-wrap gap-x-4 gap-y-1">
            {CHECKS.map((c) => (
              <label key={c} className="inline-flex items-center gap-1.5">
                <input
                  type="checkbox"
                  checked={checks.includes(c)}
                  disabled={!usable(c)}
                  onChange={() => toggle(c)}
                />
                <span className="font-mono text-xs">{c}</span>
                {!usable(c) ? (
                  <span className="gh-muted text-xs">
                    ({c === "active_ssrf" && !r.oob_configured ? t("needsOob") : t("moduleOff")})
                  </span>
                ) : null}
              </label>
            ))}
          </div>
        </fieldset>
        <div>
          <label htmlFor="owner-exclude" className="gh-label">
            {t("exclude")}
          </label>
          <textarea
            id="owner-exclude"
            className="gh-input w-80 max-w-full font-mono"
            rows={3}
            value={exclude}
            onChange={(e) => setExclude(e.target.value)}
            spellCheck={false}
          />
          <p className="gh-muted text-xs">{t("excludeHint")}</p>
        </div>
        {idor ? (
          <details className="rounded-md border p-3">
            <summary className="cursor-pointer font-semibold">{t("accounts")}</summary>
            <p className="gh-muted mt-1 text-xs">{t("accountsHint")}</p>
            <div className="mt-2 grid gap-2 sm:grid-cols-2">
              {(["a", "b"] as const).map((k) => (
                <div key={k} className="space-y-1">
                  <label className="gh-label" htmlFor={`owner-cookie-${k}`}>
                    {t("cookie", { name: k.toUpperCase() })}
                  </label>
                  <input
                    id={`owner-cookie-${k}`}
                    type="password"
                    autoComplete="off"
                    className="gh-input w-full font-mono"
                    value={k === "a" ? accounts.ca : accounts.cb}
                    onChange={(e) =>
                      setAccounts((s) =>
                        k === "a" ? { ...s, ca: e.target.value } : { ...s, cb: e.target.value },
                      )
                    }
                  />
                  <label className="gh-label" htmlFor={`owner-marker-${k}`}>
                    {t("marker", { name: k.toUpperCase() })}
                  </label>
                  <input
                    id={`owner-marker-${k}`}
                    autoComplete="off"
                    className="gh-input w-full"
                    value={k === "a" ? accounts.ma : accounts.mb}
                    onChange={(e) =>
                      setAccounts((s) =>
                        k === "a" ? { ...s, ma: e.target.value } : { ...s, mb: e.target.value },
                      )
                    }
                  />
                </div>
              ))}
            </div>
          </details>
        ) : null}
        <label className="flex items-start gap-2">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(e) => setConfirmed(e.target.checked)}
          />
          <span>{t("confirm")}</span>
        </label>
        <button
          type="submit"
          className="gh-btn gh-btn-primary"
          disabled={blocked || busy || !confirmed || !target || checks.length === 0}
        >
          {t("start")}
        </button>
      </form>
      {started ? (
        <p role="status">
          {t("started", { origin: started.origin })}{" "}
          <span className="font-mono text-xs">{started.scan_id}</span>
        </p>
      ) : null}
      {error ? (
        <p role="alert" className="text-red-800 dark:text-red-200">
          {error}
        </p>
      ) : null}
    </div>
  );
}
