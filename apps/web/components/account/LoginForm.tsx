"use client";
/**
 * Login. Both MFA outcomes continue on /account/2fa, which picks setup or code entry from
 * the session (`totp_enabled`).
 */
import { useState, type FormEvent } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import { twoFactorUrl } from "@/lib/navigation";
import type { LoginResponse } from "@/lib/types";
import { useErrorMessage } from "@/lib/use-error-message";
import { Alert } from "@/components/ui/Alert";

export function LoginForm({ next }: { next: string }) {
  const t = useTranslations("auth");
  const tCommon = useTranslations("common");
  const router = useRouter();
  const errorMessage = useErrorMessage();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await apiFetch<LoginResponse>("/auth/login", {
        method: "POST",
        body: { email: email.trim(), password },
      });
      // "setup_required" → 2FA setup, "required" → code entry.
      router.push(twoFactorUrl(next, result.mfa === "setup_required" ? "setup" : "verify"));
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
          autoComplete="current-password"
          required
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          className="gh-input"
        />
      </div>
      {error ? (
        <Alert tone="error" label={tCommon("errorLabel")}>
          {errorMessage(error)}
        </Alert>
      ) : null}
      <button type="submit" className="gh-btn-primary w-full" disabled={busy}>
        {busy ? tCommon("working") : t("loginSubmit")}
      </button>
      <p className="gh-muted text-center text-sm">
        {t("noAccount")}{" "}
        <Link href={`/account/register?next=${encodeURIComponent(next)}`} className="gh-link">
          {t("registerLink")}
        </Link>
      </p>
    </form>
  );
}
