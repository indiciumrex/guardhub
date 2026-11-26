"use client";
/**
 * Two-factor recovery codes: the list shown once (right after setup or regeneration), and the
 * account panel to see how many are left and to make new ones with a current authenticator code.
 */
import { useState } from "react";
import { useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import { useErrorMessage } from "@/lib/use-error-message";

export function RecoveryCodeList({ codes }: { codes: string[] }) {
  const t = useTranslations("twoFactor");
  const [copied, setCopied] = useState(false);
  return (
    <section aria-labelledby="codes-h" className="gh-tone-warn space-y-3 rounded-lg border p-4">
      <h2 id="codes-h" className="font-semibold">
        {t("codesTitle")}
      </h2>
      <p className="text-sm">{t("codesHelp")}</p>
      <ul aria-label={t("codesTitle")} className="grid grid-cols-2 gap-2 font-mono text-sm">
        {codes.map((c) => (
          <li
            key={c}
            className="rounded bg-white px-2 py-1 text-slate-900 dark:bg-navy-950 dark:text-slate-100"
          >
            {c}
          </li>
        ))}
      </ul>
      <button
        type="button"
        className="gh-btn-secondary min-h-9 px-3 py-1 text-sm"
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(codes.join("\n"));
            setCopied(true);
          } catch {
            setCopied(false);
          }
        }}
      >
        {copied ? t("codesCopied") : t("codesCopy")}
      </button>
    </section>
  );
}

export function RecoveryCodesPanel({ remaining }: { remaining: number }) {
  const t = useTranslations("twoFactor");
  const errorMessage = useErrorMessage();
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fresh, setFresh] = useState<string[] | null>(null);
  return (
    <section aria-labelledby="recovery-h" className="gh-card space-y-3 p-5">
      <h2 id="recovery-h" className="text-lg font-semibold">
        {t("panelTitle")}
      </h2>
      <p className="text-sm">{t("panelRemaining", { count: remaining })}</p>
      {fresh ? (
        <RecoveryCodeList codes={fresh} />
      ) : (
        <form
          className="flex flex-wrap items-end gap-3"
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setError(null);
            try {
              const r = await apiFetch<{ codes: string[] }>("/auth/2fa/recovery-codes", {
                method: "POST",
                body: { code },
              });
              setFresh(r.codes);
            } catch (err) {
              setError(errorMessage(err));
            } finally {
              setBusy(false);
            }
          }}
        >
          <div>
            <label htmlFor="regen-otp" className="gh-label">
              {t("codeLabel")}
            </label>
            <input
              id="regen-otp"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              className="gh-input w-32 text-center font-mono"
            />
          </div>
          <button type="submit" className="gh-btn-secondary" disabled={busy || code.length !== 6}>
            {t("regenerate")}
          </button>
        </form>
      )}
      <p className="gh-muted text-xs">{t("panelHelp")}</p>
      {error ? (
        <p role="alert" className="text-sm text-red-800 dark:text-red-200">
          {error}
        </p>
      ) : null}
    </section>
  );
}
