"use client";
/**
 * "Send test" per alert channel: POST /account/notifications/test {"channel"} → 202
 * (docs/architecture.md §8.4). The API allows 3 tests per hour; a 429 gets its own plain
 * message. Each channel keeps its own result, announced politely.
 */
import { useState } from "react";
import { useTranslations } from "next-intl";
import { ApiError, apiFetch } from "@/lib/api";
import type { NotificationChannel } from "@/lib/types";
import { useErrorMessage } from "@/lib/use-error-message";
import { Alert } from "@/components/ui/Alert";

type Outcome = { kind: "sent" } | { kind: "error"; message: string };

const CHANNELS: readonly NotificationChannel[] = ["email", "slack"];

export function NotificationTestButtons({ slackConfigured }: { slackConfigured: boolean }) {
  const t = useTranslations("notifications");
  const tCommon = useTranslations("common");
  const errorMessage = useErrorMessage();
  const [busy, setBusy] = useState<NotificationChannel | null>(null);
  const [outcomes, setOutcomes] = useState<Partial<Record<NotificationChannel, Outcome>>>({});

  async function sendTest(channel: NotificationChannel) {
    setBusy(channel);
    setOutcomes((current) => ({ ...current, [channel]: undefined }));
    try {
      await apiFetch<unknown>("/account/notifications/test", {
        method: "POST",
        body: { channel },
      });
      setOutcomes((current) => ({ ...current, [channel]: { kind: "sent" } }));
    } catch (err) {
      const message =
        err instanceof ApiError && err.status === 429 ? t("testRateLimited") : errorMessage(err);
      setOutcomes((current) => ({ ...current, [channel]: { kind: "error", message } }));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="grid gap-4 sm:grid-cols-2">
      {CHANNELS.map((channel) => {
        const unavailable = channel === "slack" && !slackConfigured;
        const outcome = outcomes[channel];
        const hintId = `test-${channel}-hint`;
        return (
          <div key={channel} className="space-y-3">
            <button
              type="button"
              className="gh-btn-secondary"
              onClick={() => sendTest(channel)}
              disabled={busy !== null || unavailable}
              aria-describedby={unavailable ? hintId : undefined}
            >
              {busy === channel
                ? tCommon("working")
                : channel === "email"
                  ? t("testEmail")
                  : t("testSlack")}
            </button>
            {unavailable ? (
              <p id={hintId} className="gh-muted text-sm">
                {t("testSlackNeedsSetup")}
              </p>
            ) : null}
            {outcome?.kind === "sent" ? (
              <Alert tone="success" label={t(`channel.${channel}`)}>
                {t("testSent")}
              </Alert>
            ) : null}
            {outcome?.kind === "error" ? (
              <Alert tone="error" label={tCommon("errorLabel")}>
                {outcome.message}
              </Alert>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}
