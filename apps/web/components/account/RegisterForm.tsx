"use client";
/**
 * Registration: email + password (≥ 12 characters, with a strength hint). The account locale
 * is the current UI locale. Continues to mandatory 2FA setup.
 */
import { useState, type FormEvent } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useLocale, useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import { twoFactorUrl } from "@/lib/navigation";
import { MIN_PASSWORD_LENGTH, passwordStrength, type PasswordStrength } from "@/lib/password";
import type { RegisterResponse } from "@/lib/types";
import { useErrorMessage } from "@/lib/use-error-message";
import { Alert } from "@/components/ui/Alert";

const meterWidth: Record<PasswordStrength, string> = {
  tooShort: "w-1/12",
  weak: "w-1/3",
  fair: "w-2/3",
  strong: "w-full",
};

const meterColour: Record<PasswordStrength, string> = {
  tooShort: "bg-red-600",
  weak: "bg-red-600",
  fair: "bg-amber-500",
  strong: "bg-emerald-600",
};

export function RegisterForm({ next }: { next: string }) {
  const t = useTranslations("auth");
  const tCommon = useTranslations("common");
  const locale = useLocale();
  const router = useRouter();
  const errorMessage = useErrorMessage();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const strength = passwordStrength(password);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (password.length < MIN_PASSWORD_LENGTH) return;
    setBusy(true);
    setError(null);
    try {
      await apiFetch<RegisterResponse>("/auth/register", {
        method: "POST",
        body: { email: email.trim(), password, locale },
      });
      router.push(twoFactorUrl(next, "setup"));
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <div>
        <label htmlFor="email" className="gh-label">
          {t("email")}
        </label>
        <input
          id="email"
          type="email"
          autoComplete="email"
          required
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          className="gh-input"
        />
      </div>
      <div>
        <label htmlFor="password" className="gh-label">
          {t("password")}
        </label>
        <input
          id="password"
          type="password"
          autoComplete="new-password"
          required
          minLength={MIN_PASSWORD_LENGTH}
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          aria-describedby="password-rules password-strength"
          className="gh-input"
        />
        <p id="password-rules" className="gh-muted mt-1 text-sm">
          {t("passwordRules", { min: MIN_PASSWORD_LENGTH })}
        </p>
        {password ? (
          <div className="mt-2">
            <div
              className="h-1.5 w-full rounded-full bg-slate-200 dark:bg-navy-800"
              aria-hidden="true"
            >
              <div
                className={`h-1.5 rounded-full ${meterWidth[strength]} ${meterColour[strength]}`}
              />
            </div>
            <p id="password-strength" aria-live="polite" className="mt-1 text-sm font-medium">
              {t(`strength.${strength}`, { min: MIN_PASSWORD_LENGTH })}
            </p>
          </div>
        ) : null}
      </div>
      {error ? (
        <Alert tone="error" label={tCommon("errorLabel")}>
          {errorMessage(error)}
        </Alert>
      ) : null}
      <button
        type="submit"
        className="gh-btn-primary w-full"
        disabled={busy || password.length < MIN_PASSWORD_LENGTH}
      >
        {busy ? tCommon("working") : t("registerSubmit")}
      </button>
      <p className="gh-muted text-center text-sm">
        {t("haveAccount")}{" "}
        <Link href={`/account/login?next=${encodeURIComponent(next)}`} className="gh-link">
          {t("loginLink")}
        </Link>
      </p>
    </form>
  );
}
