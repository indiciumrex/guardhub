"use client";
/**
 * Users & sessions (Prompt 2 §5): disable / enable an account, see and end its sessions, invite
 * an admin (the one-time link is shown once) and revoke an invitation. The API enforces every
 * rule (never yourself, never the last admin, invitations bound to one e-mail and 2FA) and audits.
 */
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useFormatter, useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import type { AccountSession } from "@/lib/admin-types";
import { useErrorMessage } from "@/lib/use-error-message";

function useAction() {
  const errorMessage = useErrorMessage();
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function run<T>(path: string, method: "GET" | "POST", body?: object): Promise<T | null> {
    setBusy(true);
    setError(null);
    try {
      const r = await apiFetch<T>(path, { method, body });
      if (method === "POST") router.refresh();
      return r;
    } catch (err) {
      setError(errorMessage(err));
      return null;
    } finally {
      setBusy(false);
    }
  }
  return { busy, error, run };
}

function ErrorText({ error }: { error: string | null }) {
  return error ? (
    <p role="alert" className="text-xs text-red-800 dark:text-red-200">
      {error}
    </p>
  ) : null;
}

export function AccountActions({
  userId,
  email,
  disabled,
  isSelf,
}: {
  userId: string;
  email: string;
  disabled: boolean;
  isSelf: boolean;
}) {
  const t = useTranslations("adminCenter.people");
  const format = useFormatter();
  const { busy, error, run } = useAction();
  const [reason, setReason] = useState("");
  const [list, setList] = useState<AccountSession[] | null>(null);
  const base = `/admin/people/${encodeURIComponent(userId)}`;
  const loadSessions = async () => setList(await run<AccountSession[]>(`${base}/sessions`, "GET"));
  const at = (s: number) =>
    format.dateTime(new Date(s * 1000), {
      dateStyle: "medium",
      timeStyle: "short",
      timeZone: "UTC",
    });

  return (
    <div className="space-y-2 text-xs">
      <div className="flex flex-wrap items-center gap-2">
        {disabled ? (
          <button
            type="button"
            className="gh-btn-secondary min-h-9 px-3 py-1"
            aria-label={t("enableNamed", { email })}
            disabled={busy}
            onClick={() => void run(`${base}/enable`, "POST")}
          >
            {t("enable")}
          </button>
        ) : isSelf ? null : (
          <>
            <label htmlFor={`reason-${userId}`} className="sr-only">
              {t("reason")}
            </label>
            <input
              id={`reason-${userId}`}
              value={reason}
              maxLength={200}
              placeholder={t("reasonPlaceholder")}
              disabled={busy}
              onChange={(e) => setReason(e.target.value)}
              className="gh-input w-40 py-1 text-xs"
            />
            <button
              type="button"
              className="gh-btn-secondary min-h-9 px-3 py-1"
              aria-label={t("disableNamed", { email })}
              disabled={busy}
              onClick={() => void run(`${base}/disable`, "POST", { reason })}
            >
              {t("disable")}
            </button>
          </>
        )}
        <button
          type="button"
          className="gh-btn-secondary min-h-9 px-3 py-1"
          aria-expanded={list !== null}
          aria-label={t("sessionsNamed", { email })}
          disabled={busy}
          onClick={() => (list === null ? void loadSessions() : setList(null))}
        >
          {list === null ? t("showSessions") : t("hideSessions")}
        </button>
      </div>
      {list !== null ? (
        list.length === 0 ? (
          <p className="gh-muted">{t("noSessions")}</p>
        ) : (
          <ul aria-label={t("sessionsOf", { email })} className="space-y-1">
            {list.map((s) => (
              <li key={s.jti} className="flex flex-wrap items-center gap-2">
                <span>{s.client || "-"}</span>
                <span className="gh-muted">
                  {t("sessionSince", { when: at(s.issued_at) })} ·{" "}
                  {t("sessionUntil", { when: at(s.expires_at) })} ·{" "}
                  <span className="font-mono">{s.ip_hash}</span>
                </span>
                <button
                  type="button"
                  className="gh-btn-secondary min-h-8 px-2 py-0.5"
                  disabled={busy}
                  onClick={async () => {
                    if (await run(`${base}/sessions/end`, "POST", { jti: s.jti }))
                      await loadSessions();
                  }}
                >
                  {t("endSession")}
                </button>
              </li>
            ))}
            <li>
              <button
                type="button"
                className="gh-btn-secondary min-h-8 px-2 py-0.5"
                disabled={busy}
                onClick={async () => {
                  if (await run(`${base}/sessions/end`, "POST", {})) await loadSessions();
                }}
              >
                {t("endAll")}
              </button>
            </li>
          </ul>
        )
      ) : null}
      <ErrorText error={error} />
    </div>
  );
}

export function InviteAdmin() {
  const t = useTranslations("adminCenter.people");
  const { busy, error, run } = useAction();
  const [email, setEmail] = useState("");
  const [link, setLink] = useState<string | null>(null);
  return (
    <div className="space-y-3">
      {link ? (
        <div role="status" className="gh-tone-warn rounded-lg border p-4 text-sm">
          <p className="font-semibold">{t("linkOnce")}</p>
          <p className="mt-1 text-xs">{t("linkHelp")}</p>
          <code
            aria-label={t("inviteLink")}
            className="mt-2 block rounded bg-white px-2 py-1 font-mono text-xs break-all text-slate-900 dark:bg-navy-950 dark:text-slate-100"
          >
            {link}
          </code>
          <button
            type="button"
            className="gh-btn-secondary mt-2 min-h-9 px-3 py-1 text-xs"
            onClick={() => setLink(null)}
          >
            {t("done")}
          </button>
        </div>
      ) : null}
      <form
        aria-label={t("inviteTitle")}
        className="flex flex-wrap items-end gap-3 text-sm"
        onSubmit={async (e) => {
          e.preventDefault();
          const r = await run<{ link: string }>("/admin/people/invites", "POST", {
            email: email.trim(),
          });
          if (r) {
            setLink(r.link);
            setEmail("");
          }
        }}
      >
        <div>
          <label htmlFor="invite-email" className="block font-medium">
            {t("inviteEmail")}
          </label>
          <input
            id="invite-email"
            type="email"
            value={email}
            disabled={busy}
            onChange={(e) => setEmail(e.target.value)}
            className="gh-input mt-1 w-64 py-1.5"
          />
        </div>
        <button
          type="submit"
          className="gh-btn-primary min-h-9 px-3 py-1.5"
          disabled={busy || !email.includes("@")}
        >
          {t("createInvite")}
        </button>
      </form>
      <ErrorText error={error} />
    </div>
  );
}

export function RevokeInvite({ inviteId, email }: { inviteId: string; email: string }) {
  const t = useTranslations("adminCenter.people");
  const { busy, error, run } = useAction();
  return (
    <span className="inline-flex flex-col items-start gap-1">
      <button
        type="button"
        className="gh-btn-secondary min-h-9 px-3 py-1 text-xs"
        aria-label={t("revokeInviteNamed", { email })}
        disabled={busy}
        onClick={() =>
          void run(`/admin/people/invites/${encodeURIComponent(inviteId)}/revoke`, "POST")
        }
      >
        {t("revokeInvite")}
      </button>
      <ErrorText error={error} />
    </span>
  );
}

export function AcceptAdminInvite({ token }: { token: string }) {
  const t = useTranslations("adminInvite");
  const errorMessage = useErrorMessage();
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <div className="space-y-3">
      <button
        type="button"
        className="gh-btn-primary"
        disabled={busy || !token}
        onClick={async () => {
          setBusy(true);
          setError(null);
          try {
            await apiFetch("/auth/admin-invite/accept", { method: "POST", body: { token } });
            router.push("/admin");
            router.refresh();
          } catch (err) {
            setError(errorMessage(err));
          } finally {
            setBusy(false);
          }
        }}
      >
        {t("accept")}
      </button>
      <ErrorText error={error} />
    </div>
  );
}
