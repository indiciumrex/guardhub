"use client";
/**
 * Two-factor authentication (mandatory, §9.1).
 * - setup: asks the API for a TOTP secret, renders the otpauth:// QR code client-side
 *   (the secret never leaves the browser/API pair) and shows the secret as text.
 * - verify: 6-digit code entry, or a single-use recovery code instead.
 * - right after setup, the ten recovery codes are shown once, before going on.
 */
import { useEffect, useRef, useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import QRCode from "qrcode";
import { apiFetch } from "@/lib/api";
import type { TotpSetupResponse, VerifyTotpResponse } from "@/lib/types";
import { useErrorMessage } from "@/lib/use-error-message";
import { Alert } from "@/components/ui/Alert";
import { RecoveryCodeList } from "./RecoveryCodes";

export function TwoFactorForm({ mode, next }: { mode: "setup" | "verify"; next: string }) {
  const t = useTranslations("twoFactor");
  const tCommon = useTranslations("common");
  const router = useRouter();
  const errorMessage = useErrorMessage();
  const [setup, setSetup] = useState<TotpSetupResponse | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [useRecovery, setUseRecovery] = useState(false);
  const [codes, setCodes] = useState<string[] | null>(null);
  const requested = useRef(false);

  useEffect(() => {
    if (mode !== "setup" || requested.current) return;
    requested.current = true; // one secret per visit, even under StrictMode double effects
    apiFetch<TotpSetupResponse>("/auth/2fa/setup", { method: "POST" })
      .then(async (result) => {
        setSetup(result);
        setQr(
          await QRCode.toDataURL(result.otpauth_uri, {
            margin: 1,
            width: 224,
            errorCorrectionLevel: "M",
          }),
        );
      })
      .catch((err: unknown) => setError(err));
  }, [mode]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await apiFetch<VerifyTotpResponse & { recovery_codes?: string[] | null }>(
        useRecovery ? "/auth/2fa/recover" : "/auth/2fa/verify",
        { method: "POST", body: { code } },
      );
      if (r.recovery_codes?.length) {
        setCodes(r.recovery_codes); // shown once: the user continues after saving them
        setBusy(false);
        return;
      }
      router.replace(next);
      router.refresh();
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  }

  if (codes) {
    return (
      <div className="space-y-4">
        <RecoveryCodeList codes={codes} />
        <button
          type="button"
          className="gh-btn-primary w-full"
          onClick={() => {
            router.replace(next);
            router.refresh();
          }}
        >
          {t("codesSaved")}
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {mode === "setup" ? (
        <section aria-labelledby="setup-heading" className="space-y-3">
          <h2 id="setup-heading" className="font-semibold">
            {t("setupHeading")}
          </h2>
          <ol className="gh-muted list-decimal space-y-1 pl-5 text-sm">
            <li>{t("setupStep1")}</li>
            <li>{t("setupStep2")}</li>
            <li>{t("setupStep3")}</li>
          </ol>
          {setup && qr ? (
            <div className="flex flex-col items-center gap-3">
              {/* eslint-disable-next-line @next/next/no-img-element -- data: URI generated locally */}
              <img
                src={qr}
                width={224}
                height={224}
                alt={t("qrAlt")}
                className="rounded-lg border border-slate-200 bg-white p-2"
              />
              <div className="w-full">
                <p className="gh-label">{t("secretLabel")}</p>
                <code className="block w-full rounded-md bg-slate-100 px-3 py-2 text-center font-mono text-sm break-all tracking-wider dark:bg-navy-800">
                  {setup.secret}
                </code>
              </div>
            </div>
          ) : !error ? (
            <p role="status" className="gh-muted text-sm">
              {tCommon("loading")}
            </p>
          ) : null}
        </section>
      ) : null}

      <form onSubmit={submit} className="space-y-4">
        {useRecovery ? (
          <div>
            <label htmlFor="recovery" className="gh-label">
              {t("recoveryLabel")}
            </label>
            <input
              id="recovery"
              name="recovery"
              type="text"
              autoComplete="off"
              maxLength={20}
              required
              value={code}
              onChange={(event) => setCode(event.target.value.slice(0, 20))}
              aria-describedby="recovery-hint"
              className="gh-input text-center font-mono text-lg tracking-wider"
            />
            <p id="recovery-hint" className="gh-muted mt-1 text-sm">
              {t("recoveryHint")}
            </p>
          </div>
        ) : (
          <div>
            <label htmlFor="otp" className="gh-label">
              {t("codeLabel")}
            </label>
            <input
              id="otp"
              name="otp"
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6}"
              maxLength={6}
              required
              value={code}
              onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))}
              aria-describedby="otp-hint"
              className="gh-input text-center font-mono text-lg tracking-[0.4em]"
            />
            <p id="otp-hint" className="gh-muted mt-1 text-sm">
              {t("codeHint")}
            </p>
          </div>
        )}
        {error ? (
          <Alert tone="error" label={tCommon("errorLabel")}>
            {errorMessage(error)}
          </Alert>
        ) : null}
        <button
          type="submit"
          className="gh-btn-primary w-full"
          disabled={
            busy || (useRecovery ? code.replace(/[^a-z0-9]/gi, "").length < 10 : code.length !== 6)
          }
        >
          {busy ? tCommon("working") : t("submit")}
        </button>
        {mode === "verify" ? (
          <button
            type="button"
            className="gh-link text-sm"
            onClick={() => {
              setUseRecovery((v) => !v);
              setCode("");
              setError(null);
            }}
          >
            {useRecovery ? t("useAuthenticator") : t("useRecovery")}
          </button>
        ) : null}
      </form>
    </div>
  );
}
