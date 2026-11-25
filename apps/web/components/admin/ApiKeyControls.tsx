"use client";
/**
 * Integration API keys (Prompt 2 §4): create a key (name, scopes, expiry) and see its secret
 * exactly once; revoke a key. The API stores only a keyed hash and audits both actions.
 */
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import {
  API_KEY_DAYS,
  API_KEY_SCOPES,
  type ApiKeyScope,
  type CreatedApiKey,
} from "@/lib/admin-types";
import { useErrorMessage } from "@/lib/use-error-message";

export function CreateApiKey() {
  const t = useTranslations("adminCenter.integrations");
  const errorMessage = useErrorMessage();
  const router = useRouter();
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<ApiKeyScope[]>(["scans:read"]);
  const [days, setDays] = useState<number>(90);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<CreatedApiKey | null>(null);
  const [copied, setCopied] = useState(false);

  async function create() {
    setBusy(true);
    setError(null);
    try {
      const r = await apiFetch<CreatedApiKey>("/admin/integrations/keys", {
        method: "POST",
        body: { name: name.trim(), scopes, expires_in_days: days },
      });
      setCreated(r);
      setCopied(false);
      setName("");
      router.refresh();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      {created ? (
        <div role="status" className="gh-tone-warn rounded-lg border p-4 text-sm">
          <p className="font-semibold">{t("secretOnce", { name: created.key.name })}</p>
          <p className="mt-1 text-xs">{t("secretWarning")}</p>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <code
              aria-label={t("secretLabel")}
              className="rounded bg-white px-2 py-1 font-mono text-xs break-all text-slate-900 dark:bg-navy-950 dark:text-slate-100"
            >
              {created.secret}
            </code>
            <button
              type="button"
              className="gh-btn-secondary min-h-9 px-3 py-1 text-xs"
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(created.secret);
                  setCopied(true);
                } catch {
                  setCopied(false);
                }
              }}
            >
              {copied ? t("copied") : t("copy")}
            </button>
            <button
              type="button"
              className="gh-btn-secondary min-h-9 px-3 py-1 text-xs"
              onClick={() => setCreated(null)}
            >
              {t("done")}
            </button>
          </div>
        </div>
      ) : null}
      <form
        aria-label={t("createTitle")}
        className="flex flex-wrap items-end gap-4 text-sm"
        onSubmit={(e) => {
          e.preventDefault();
          void create();
        }}
      >
        <div>
          <label htmlFor="key-name" className="block font-medium">
            {t("keyName")}
          </label>
          <input
            id="key-name"
            value={name}
            maxLength={80}
            disabled={busy}
            onChange={(e) => setName(e.target.value)}
            className="gh-input mt-1 w-56 py-1.5"
          />
        </div>
        <fieldset>
          <legend className="font-medium">{t("scopesLabel")}</legend>
          <div className="mt-1 flex flex-wrap gap-3">
            {API_KEY_SCOPES.map((s) => (
              <label key={s} className="inline-flex min-h-9 items-center gap-2">
                <input
                  type="checkbox"
                  checked={scopes.includes(s)}
                  disabled={busy}
                  onChange={(e) =>
                    setScopes((cur) =>
                      e.target.checked ? [...cur, s] : cur.filter((x) => x !== s),
                    )
                  }
                  className="h-4 w-4"
                />
                <span>{t(`scope.${s.replace(":", "_")}`)}</span>
              </label>
            ))}
          </div>
        </fieldset>
        <div>
          <label htmlFor="key-days" className="block font-medium">
            {t("expiresIn")}
          </label>
          <select
            id="key-days"
            value={days}
            disabled={busy}
            onChange={(e) => setDays(Number(e.target.value))}
            className="gh-input mt-1 w-auto min-w-28 py-1.5"
          >
            {API_KEY_DAYS.map((d) => (
              <option key={d} value={d}>
                {t("daysOption", { days: d })}
              </option>
            ))}
          </select>
        </div>
        <button
          type="submit"
          className="gh-btn-primary min-h-9 px-3 py-1.5"
          disabled={busy || !name.trim() || scopes.length === 0}
        >
          {t("create")}
        </button>
      </form>
      {error ? (
        <p role="alert" className="text-xs text-red-800 dark:text-red-200">
          {error}
        </p>
      ) : null}
    </div>
  );
}

export function RevokeApiKey({ keyId, name }: { keyId: string; name: string }) {
  const t = useTranslations("adminCenter.integrations");
  const errorMessage = useErrorMessage();
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <span className="inline-flex flex-col items-start gap-1">
      <button
        type="button"
        className="gh-btn-secondary min-h-9 px-3 py-1 text-xs"
        aria-label={t("revokeNamed", { name })}
        disabled={busy}
        onClick={async () => {
          setBusy(true);
          setError(null);
          try {
            await apiFetch(`/admin/integrations/keys/${encodeURIComponent(keyId)}/revoke`, {
              method: "POST",
            });
            router.refresh();
          } catch (err) {
            setError(errorMessage(err));
          } finally {
            setBusy(false);
          }
        }}
      >
        {t("revoke")}
      </button>
      {error ? (
        <span role="alert" className="text-xs text-red-800 dark:text-red-200">
          {error}
        </span>
      ) : null}
    </span>
  );
}
