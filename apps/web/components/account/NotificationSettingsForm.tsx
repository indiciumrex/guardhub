"use client";
/**
 * Alert settings (docs/architecture.md §8.4): e-mail on/off, which changes to alert on, and an
 * optional Slack incoming webhook. The webhook is WRITE-ONLY: the API never returns it, so the
 * form only knows "connected or not" and offers replace / remove. A typed URL is checked
 * against the same pattern as the API as a hint (the server stays authoritative) and the field
 * is cleared after saving. A refresh afterwards updates the server-rendered test buttons. Saved with PUT /account/notifications through apiFetch (CSRF header).
 */
import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { ApiError, apiFetch } from "@/lib/api";
import {
  isSlackWebhookUrl,
  type NotificationSettings,
  type NotificationSettingsUpdate,
} from "@/lib/types";
import { useErrorMessage } from "@/lib/use-error-message";
import { Alert } from "@/components/ui/Alert";

type SlackMode = "keep" | "replace" | "remove";
type Toggle = "email_enabled" | "notify_new" | "notify_regression" | "notify_fixed";

function isSettings(value: unknown): value is NotificationSettings {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { slack_configured?: unknown }).slack_configured === "boolean"
  );
}

export function NotificationSettingsForm({ initial }: { initial: NotificationSettings }) {
  const t = useTranslations("notifications");
  const tCommon = useTranslations("common");
  const router = useRouter();
  const errorMessage = useErrorMessage();
  const [values, setValues] = useState<Record<Toggle, boolean>>({
    email_enabled: initial.email_enabled,
    notify_new: initial.notify_new,
    notify_regression: initial.notify_regression,
    notify_fixed: initial.notify_fixed,
  });
  const [slackConfigured, setSlackConfigured] = useState(initial.slack_configured);
  const [slackMode, setSlackMode] = useState<SlackMode>(
    initial.slack_configured ? "keep" : "replace",
  );
  const [slackUrl, setSlackUrl] = useState("");
  const [showSlackHint, setShowSlackHint] = useState(false);
  const [serverRejectedSlack, setServerRejectedSlack] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [justSaved, setJustSaved] = useState(false);

  const trimmedUrl = slackUrl.trim();
  const slackInvalid =
    serverRejectedSlack ||
    (slackMode === "replace" && trimmedUrl !== "" && !isSlackWebhookUrl(trimmedUrl));

  function toggle(key: Toggle) {
    setValues((current) => ({ ...current, [key]: !current[key] }));
    setJustSaved(false);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setJustSaved(false);
    if (slackInvalid) {
      setShowSlackHint(true);
      return;
    }
    const body: NotificationSettingsUpdate = { ...values };
    if (slackMode === "remove") body.slack_webhook_url = null;
    else if (slackMode === "replace" && trimmedUrl !== "") body.slack_webhook_url = trimmedUrl;
    // Otherwise the key is omitted: the stored webhook (if any) is kept.

    setBusy(true);
    setError(null);
    try {
      const response = await apiFetch<unknown>("/account/notifications", {
        method: "PUT",
        body,
      });
      const nowConfigured = isSettings(response)
        ? response.slack_configured
        : body.slack_webhook_url === undefined
          ? slackConfigured
          : body.slack_webhook_url !== null;
      setSlackConfigured(nowConfigured);
      setSlackMode(nowConfigured ? "keep" : "replace");
      setSlackUrl("");
      setShowSlackHint(false);
      setJustSaved(true);
      router.refresh();
    } catch (err) {
      if (err instanceof ApiError && err.code === "invalid_slack_webhook") {
        setServerRejectedSlack(true);
        setShowSlackHint(true);
      }
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  const checkbox = (key: Toggle, label: string) => (
    <div className="flex items-start gap-3">
      <input
        type="checkbox"
        id={`notify-${key}`}
        checked={values[key]}
        onChange={() => toggle(key)}
        disabled={busy}
        className="mt-1 h-4 w-4 accent-teal-700"
      />
      <label htmlFor={`notify-${key}`} className="text-sm">
        {label}
      </label>
    </div>
  );

  return (
    <form onSubmit={submit} className="space-y-6" noValidate>
      <fieldset className="space-y-2">
        <legend className="gh-label">{t("emailLegend")}</legend>
        {checkbox("email_enabled", t("emailEnabled", { email: initial.email }))}
      </fieldset>

      <fieldset className="space-y-2">
        <legend className="gh-label">{t("changesLegend")}</legend>
        {checkbox("notify_new", t("notifyNew"))}
        {checkbox("notify_regression", t("notifyRegression"))}
        {checkbox("notify_fixed", t("notifyFixed"))}
      </fieldset>

      <fieldset className="space-y-3">
        <legend className="gh-label">{t("slackLegend")}</legend>
        {slackConfigured && slackMode === "keep" ? (
          <div className="space-y-3">
            <p className="text-sm">
              <span className="font-semibold">{t("slackConnected")}</span>{" "}
              <span className="gh-muted">{t("slackHidden")}</span>
            </p>
            <div className="flex flex-wrap gap-3">
              <button
                type="button"
                className="gh-btn-secondary"
                onClick={() => setSlackMode("replace")}
                disabled={busy}
              >
                {t("slackReplace")}
              </button>
              <button
                type="button"
                className="gh-btn-secondary"
                onClick={() => setSlackMode("remove")}
                disabled={busy}
              >
                {t("slackRemove")}
              </button>
            </div>
          </div>
        ) : null}
        {slackConfigured && slackMode === "remove" ? (
          <div className="flex flex-wrap items-center gap-3">
            <p className="text-sm font-semibold" role="status">
              {t("slackWillRemove")}
            </p>
            <button
              type="button"
              className="gh-btn-secondary"
              onClick={() => setSlackMode("keep")}
              disabled={busy}
            >
              {t("slackCancel")}
            </button>
          </div>
        ) : null}
        {slackMode === "replace" ? (
          <div className="space-y-2">
            {!slackConfigured ? <p className="gh-muted text-sm">{t("slackNotConnected")}</p> : null}
            <label htmlFor="slack-webhook" className="gh-label">
              {t("slackUrlLabel")}
            </label>
            <input
              id="slack-webhook"
              name="slack-webhook"
              type="url"
              inputMode="url"
              autoComplete="off"
              spellCheck={false}
              maxLength={300}
              placeholder="https://hooks.slack.com/services/…"
              value={slackUrl}
              onChange={(event) => {
                setSlackUrl(event.target.value);
                setServerRejectedSlack(false);
                setJustSaved(false);
              }}
              onBlur={() => setShowSlackHint(true)}
              aria-invalid={showSlackHint && slackInvalid ? true : undefined}
              aria-describedby={
                showSlackHint && slackInvalid
                  ? "slack-webhook-hint slack-webhook-error"
                  : "slack-webhook-hint"
              }
              className="gh-input"
              disabled={busy}
            />
            <p id="slack-webhook-hint" className="gh-muted text-sm">
              {t("slackUrlHint")}
            </p>
            {showSlackHint && slackInvalid ? (
              <p
                id="slack-webhook-error"
                className="text-sm font-semibold text-red-800 dark:text-red-200"
              >
                {t("slackUrlInvalid")}
              </p>
            ) : null}
            {slackConfigured ? (
              <button
                type="button"
                className="gh-btn-secondary"
                onClick={() => {
                  setSlackMode("keep");
                  setSlackUrl("");
                  setShowSlackHint(false);
                  setServerRejectedSlack(false);
                }}
                disabled={busy}
              >
                {t("slackCancel")}
              </button>
            ) : null}
          </div>
        ) : null}
      </fieldset>

      {error ? (
        <Alert tone="error" label={tCommon("errorLabel")}>
          {errorMessage(error)}
        </Alert>
      ) : null}
      {justSaved ? (
        <Alert tone="success" label={t("savedLabel")}>
          {t("saved")}
        </Alert>
      ) : null}
      <button type="submit" className="gh-btn-primary" disabled={busy}>
        {busy ? tCommon("working") : t("save")}
      </button>
    </form>
  );
}
