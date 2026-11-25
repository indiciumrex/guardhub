"use client";
/**
 * Signed webhooks (Prompt 2 §4): create one (the signing secret is shown once), switch it on or
 * off, and send a test ping. The API checks the address (https, port 443, public only) and
 * audits every change.
 */
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import { WEBHOOK_EVENTS, type CreatedWebhook, type WebhookEvent } from "@/lib/admin-types";
import { useErrorMessage } from "@/lib/use-error-message";

const eventKey = (e: string) => e.replace(/\./g, "_");

function useAction() {
  const errorMessage = useErrorMessage();
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function run<T>(path: string, body?: object): Promise<T | null> {
    setBusy(true);
    setError(null);
    try {
      const r = await apiFetch<T>(path, { method: "POST", body });
      router.refresh();
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

export function CreateWebhook() {
  const t = useTranslations("adminCenter.webhooks");
  const { busy, error, run } = useAction();
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [events, setEvents] = useState<WebhookEvent[]>(["scan.completed"]);
  const [created, setCreated] = useState<CreatedWebhook | null>(null);

  return (
    <div className="space-y-4">
      {created ? (
        <div role="status" className="gh-tone-warn rounded-lg border p-4 text-sm">
          <p className="font-semibold">{t("secretOnce", { name: created.webhook.name })}</p>
          <p className="mt-1 text-xs">{t("secretHelp")}</p>
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
        onSubmit={async (e) => {
          e.preventDefault();
          const r = await run<CreatedWebhook>("/admin/webhooks", {
            name: name.trim(),
            url: url.trim(),
            events,
          });
          if (r) {
            setCreated(r);
            setName("");
            setUrl("");
          }
        }}
      >
        <div>
          <label htmlFor="hook-name" className="block font-medium">
            {t("name")}
          </label>
          <input
            id="hook-name"
            value={name}
            maxLength={80}
            disabled={busy}
            onChange={(e) => setName(e.target.value)}
            className="gh-input mt-1 w-48 py-1.5"
          />
        </div>
        <div className="min-w-0 grow">
          <label htmlFor="hook-url" className="block font-medium">
            {t("url")}
          </label>
          <input
            id="hook-url"
            type="url"
            inputMode="url"
            placeholder="https://"
            value={url}
            maxLength={2048}
            disabled={busy}
            aria-describedby="hook-url-help"
            onChange={(e) => setUrl(e.target.value)}
            className="gh-input mt-1 w-full py-1.5"
          />
          <p id="hook-url-help" className="gh-muted mt-1 text-xs">
            {t("urlHelp")}
          </p>
        </div>
        <fieldset>
          <legend className="font-medium">{t("eventsLabel")}</legend>
          <div className="mt-1 flex flex-wrap gap-3">
            {WEBHOOK_EVENTS.map((ev) => (
              <label key={ev} className="inline-flex min-h-9 items-center gap-2">
                <input
                  type="checkbox"
                  checked={events.includes(ev)}
                  disabled={busy}
                  onChange={(e) =>
                    setEvents((cur) =>
                      e.target.checked ? [...cur, ev] : cur.filter((x) => x !== ev),
                    )
                  }
                  className="h-4 w-4"
                />
                {t(`event.${eventKey(ev)}`)}
              </label>
            ))}
          </div>
        </fieldset>
        <button
          type="submit"
          className="gh-btn-primary min-h-9 px-3 py-1.5"
          disabled={
            busy || !name.trim() || !url.trim().startsWith("https://") || events.length === 0
          }
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

export function WebhookActions({
  webhookId,
  name,
  enabled,
}: {
  webhookId: string;
  name: string;
  enabled: boolean;
}) {
  const t = useTranslations("adminCenter.webhooks");
  const { busy, error, run } = useAction();
  const base = `/admin/webhooks/${encodeURIComponent(webhookId)}`;
  return (
    <div className="flex flex-col items-start gap-1">
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          className="gh-btn-secondary min-h-9 px-3 py-1 text-xs"
          aria-label={t(enabled ? "disableNamed" : "enableNamed", { name })}
          disabled={busy}
          onClick={() => void run(`${base}/enabled`, { enabled: !enabled })}
        >
          {enabled ? t("disable") : t("enable")}
        </button>
        {enabled ? (
          <button
            type="button"
            className="gh-btn-secondary min-h-9 px-3 py-1 text-xs"
            aria-label={t("pingNamed", { name })}
            disabled={busy}
            onClick={() => void run(`${base}/ping`)}
          >
            {t("ping")}
          </button>
        ) : null}
      </div>
      {error ? (
        <span role="alert" className="text-xs text-red-800 dark:text-red-200">
          {error}
        </span>
      ) : null}
    </div>
  );
}
