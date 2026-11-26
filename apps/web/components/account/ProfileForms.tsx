"use client";
/**
 * The account holder's own profile (display name) and password. A password change needs the
 * current password AND a current authenticator code; it signs out every other device and keeps
 * this one. There is no password-less path here (no e-mail link, no admin override).
 */
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import { useErrorMessage } from "@/lib/use-error-message";

function Alert({ text, tone }: { text: string | null; tone: "ok" | "error" }) {
  if (!text) return null;
  return tone === "ok" ? (
    <p role="status" className="text-sm text-emerald-800 dark:text-emerald-200">
      {text}
    </p>
  ) : (
    <p role="alert" className="text-sm text-red-800 dark:text-red-200">
      {text}
    </p>
  );
}

export function DisplayNameForm({ current }: { current: string | null }) {
  const t = useTranslations("profile");
  const errorMessage = useErrorMessage();
  const router = useRouter();
  const [name, setName] = useState(current ?? "");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ text: string; tone: "ok" | "error" } | null>(null);
  return (
    <form
      className="flex flex-wrap items-end gap-3"
      onSubmit={async (e) => {
        e.preventDefault();
        setBusy(true);
        setMsg(null);
        try {
          await apiFetch("/auth/me", { method: "PATCH", body: { display_name: name.trim() } });
          setMsg({ text: t("saved"), tone: "ok" });
          router.refresh();
        } catch (err) {
          setMsg({ text: errorMessage(err), tone: "error" });
        } finally {
          setBusy(false);
        }
      }}
    >
      <div className="min-w-64 flex-1">
        <label htmlFor="display-name" className="gh-label">
          {t("nameLabel")}
        </label>
        <input
          id="display-name"
          value={name}
          maxLength={80}
          autoComplete="name"
          onChange={(e) => setName(e.target.value)}
          className="gh-input w-full"
        />
      </div>
      <button type="submit" className="gh-btn-secondary" disabled={busy}>
        {t("save")}
      </button>
      <div className="w-full">
        <Alert text={msg?.text ?? null} tone={msg?.tone ?? "ok"} />
      </div>
    </form>
  );
}

export function ChangePasswordForm() {
  const t = useTranslations("profile");
  const errorMessage = useErrorMessage();
  const router = useRouter();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ text: string; tone: "ok" | "error" } | null>(null);
  const mismatch = confirm.length > 0 && confirm !== next;
  return (
    <form
      aria-label={t("passwordTitle")}
      className="grid max-w-xl gap-3"
      onSubmit={async (e) => {
        e.preventDefault();
        if (next !== confirm) return;
        setBusy(true);
        setMsg(null);
        try {
          const r = await apiFetch<{ sessions_ended: number }>("/auth/password", {
            method: "POST",
            body: { current_password: current, new_password: next, code },
          });
          setCurrent("");
          setNext("");
          setConfirm("");
          setCode("");
          setMsg({ text: t("passwordChanged", { count: r.sessions_ended }), tone: "ok" });
          router.refresh();
        } catch (err) {
          setMsg({ text: errorMessage(err), tone: "error" });
        } finally {
          setBusy(false);
        }
      }}
    >
      <div>
        <label htmlFor="pw-current" className="gh-label">
          {t("currentPassword")}
        </label>
        <input
          id="pw-current"
          type="password"
          autoComplete="current-password"
          value={current}
          onChange={(e) => setCurrent(e.target.value)}
          className="gh-input w-full"
          required
        />
      </div>
      <div>
        <label htmlFor="pw-new" className="gh-label">
          {t("newPassword")}
        </label>
        <input
          id="pw-new"
          type="password"
          autoComplete="new-password"
          value={next}
          minLength={12}
          maxLength={128}
          onChange={(e) => setNext(e.target.value)}
          className="gh-input w-full"
          aria-describedby="pw-new-help"
          required
        />
        <p id="pw-new-help" className="gh-muted mt-1 text-xs">
          {t("newPasswordHelp")}
        </p>
      </div>
      <div>
        <label htmlFor="pw-confirm" className="gh-label">
          {t("confirmPassword")}
        </label>
        <input
          id="pw-confirm"
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          className="gh-input w-full"
          aria-invalid={mismatch}
          required
        />
        {mismatch ? (
          <p className="mt-1 text-xs text-red-800 dark:text-red-200">{t("mismatch")}</p>
        ) : null}
      </div>
      <div>
        <label htmlFor="pw-otp" className="gh-label">
          {t("code")}
        </label>
        <input
          id="pw-otp"
          inputMode="numeric"
          autoComplete="one-time-code"
          maxLength={6}
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
          className="gh-input w-32 text-center font-mono"
          required
        />
      </div>
      <p className="gh-muted text-xs">{t("passwordHelp")}</p>
      <div>
        <button
          type="submit"
          className="gh-btn-primary"
          disabled={busy || !current || !next || mismatch || code.length !== 6}
        >
          {t("changePassword")}
        </button>
      </div>
      <Alert text={msg?.text ?? null} tone={msg?.tone ?? "ok"} />
    </form>
  );
}
