"use client";
/**
 * The signed-in account's own sessions (Phase 5A): where it is signed in, and ending one or all
 * of them ("sign out everywhere"). The API only ever lists and ends this account's sessions.
 */
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useFormatter, useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import type { AccountSession } from "@/lib/admin-types";
import { useErrorMessage } from "@/lib/use-error-message";

export function OwnSessions({ sessions }: { sessions: AccountSession[] }) {
  const t = useTranslations("customer.security");
  const format = useFormatter();
  const errorMessage = useErrorMessage();
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const at = (s: number) =>
    format.dateTime(new Date(s * 1000), {
      dateStyle: "medium",
      timeStyle: "short",
      timeZone: "UTC",
    });

  async function end(jti: string | null) {
    setBusy(true);
    setError(null);
    try {
      await apiFetch("/auth/sessions/end", { method: "POST", body: jti ? { jti } : {} });
      if (jti === null) router.push("/account/login");
      router.refresh();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-3">
      {sessions.length === 0 ? (
        <p className="gh-muted text-sm">{t("noSessions")}</p>
      ) : (
        <ul
          aria-label={t("sessionsTitle")}
          className="divide-y divide-slate-200 dark:divide-navy-800"
        >
          {sessions.map((s) => (
            <li
              key={s.jti}
              className="flex flex-wrap items-center justify-between gap-2 py-2 text-sm"
            >
              <span>
                <span className="font-medium">{s.client || "-"}</span>
                <span className="gh-muted block text-xs">
                  {t("since", { when: at(s.issued_at) })} · {t("until", { when: at(s.expires_at) })}
                </span>
              </span>
              <button
                type="button"
                className="gh-btn-secondary min-h-9 px-3 py-1 text-xs"
                disabled={busy}
                onClick={() => void end(s.jti)}
              >
                {t("end")}
              </button>
            </li>
          ))}
        </ul>
      )}
      <button
        type="button"
        className="gh-btn-secondary min-h-9 px-3 py-1.5 text-sm"
        disabled={busy}
        onClick={() => void end(null)}
      >
        {t("endAll")}
      </button>
      {error ? (
        <p role="alert" className="text-sm text-red-800 dark:text-red-200">
          {error}
        </p>
      ) : null}
    </div>
  );
}
