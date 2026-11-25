"use client";
/**
 * Operational alerts (Prompt 2 §2): acknowledge / resolve one alert, and edit one alert rule
 * (on/off, threshold, window, e-mail, escalation, mute). The API validates and audits each change.
 */
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import type { OpsAlertRule } from "@/lib/admin-types";
import { useErrorMessage } from "@/lib/use-error-message";

function useAction() {
  const errorMessage = useErrorMessage();
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function run(path: string, method: "POST" | "PUT", body?: object) {
    setBusy(true);
    setError(null);
    try {
      await apiFetch(path, { method, body });
      router.refresh();
    } catch (err) {
      setError(errorMessage(err));
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

export function OpsAlertActions({
  alertId,
  acknowledged,
}: {
  alertId: string;
  acknowledged: boolean;
}) {
  const t = useTranslations("adminCenter.alerts");
  const { busy, error, run } = useAction();
  const base = `/admin/alerts/${encodeURIComponent(alertId)}`;
  return (
    <div className="flex flex-col items-start gap-1">
      <div className="flex flex-wrap gap-2">
        {acknowledged ? null : (
          <button
            type="button"
            className="gh-btn-primary min-h-9 px-3 py-1 text-xs"
            disabled={busy}
            onClick={() => void run(`${base}/acknowledge`, "POST")}
          >
            {t("acknowledge")}
          </button>
        )}
        <button
          type="button"
          className="gh-btn-secondary min-h-9 px-3 py-1 text-xs"
          disabled={busy}
          onClick={() => void run(`${base}/resolve`, "POST")}
        >
          {t("resolve")}
        </button>
      </div>
      <ErrorText error={error} />
    </div>
  );
}

const MUTE = [60, 240, 1440] as const;

export function OpsAlertRuleForm({ rule, label }: { rule: OpsAlertRule; label: string }) {
  const t = useTranslations("adminCenter.alerts");
  const { busy, error, run } = useAction();
  const [enabled, setEnabled] = useState(rule.enabled);
  const [threshold, setThreshold] = useState(String(rule.threshold));
  const [windowMinutes, setWindowMinutes] = useState(String(rule.window_minutes));
  const [email, setEmail] = useState(rule.email);
  const [escalate, setEscalate] = useState(
    rule.escalate_after_minutes === null ? "" : String(rule.escalate_after_minutes),
  );
  const id = `rule-${rule.kind}`;
  const usesWindow = rule.kind !== "worker_offline";
  const n = (v: string) => Number(v);
  const valid =
    Number.isInteger(n(threshold)) &&
    n(threshold) >= 1 &&
    n(threshold) <= 1000 &&
    Number.isInteger(n(windowMinutes)) &&
    n(windowMinutes) >= 5 &&
    n(windowMinutes) <= 1440 &&
    (escalate === "" || (Number.isInteger(n(escalate)) && n(escalate) >= 5 && n(escalate) <= 1440));
  const base = `/admin/alerts/rules/${rule.kind}`;

  return (
    <form
      aria-label={label}
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        void run(base, "PUT", {
          enabled,
          threshold: n(threshold),
          window_minutes: n(windowMinutes),
          email,
          escalate_after_minutes: escalate === "" ? null : n(escalate),
        });
      }}
    >
      <label className="inline-flex min-h-11 items-center gap-3 text-sm font-medium">
        <input
          type="checkbox"
          role="switch"
          aria-checked={enabled}
          checked={enabled}
          disabled={busy}
          onChange={(e) => setEnabled(e.target.checked)}
          className="h-5 w-5"
        />
        {t("ruleOn")}
      </label>
      <div className="flex flex-wrap items-end gap-3 text-sm">
        <div>
          <label htmlFor={`${id}-threshold`} className="block font-medium">
            {t(`thresholdLabel.${rule.kind}`)}
          </label>
          <input
            id={`${id}-threshold`}
            type="number"
            min={1}
            max={1000}
            value={threshold}
            disabled={busy}
            onChange={(e) => setThreshold(e.target.value)}
            className="gh-input mt-1 w-28 py-1.5"
          />
        </div>
        {usesWindow ? (
          <div>
            <label htmlFor={`${id}-window`} className="block font-medium">
              {t("windowLabel")}
            </label>
            <input
              id={`${id}-window`}
              type="number"
              min={5}
              max={1440}
              value={windowMinutes}
              disabled={busy}
              onChange={(e) => setWindowMinutes(e.target.value)}
              className="gh-input mt-1 w-28 py-1.5"
            />
          </div>
        ) : null}
        <div>
          <label htmlFor={`${id}-escalate`} className="block font-medium">
            {t("escalateLabel")}
          </label>
          <input
            id={`${id}-escalate`}
            type="number"
            min={5}
            max={1440}
            placeholder={t("escalateOff")}
            value={escalate}
            disabled={busy}
            onChange={(e) => setEscalate(e.target.value)}
            className="gh-input mt-1 w-28 py-1.5"
          />
        </div>
        <label className="inline-flex min-h-11 items-center gap-2">
          <input
            type="checkbox"
            checked={email}
            disabled={busy}
            onChange={(e) => setEmail(e.target.checked)}
            className="h-4 w-4"
          />
          {t("emailChannel")}
        </label>
        <button
          type="submit"
          className="gh-btn-primary min-h-9 px-3 py-1.5"
          disabled={busy || !valid}
        >
          {t("saveRule")}
        </button>
      </div>
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="gh-muted">{t("muteLabel")}</span>
        {MUTE.map((m) => (
          <button
            key={m}
            type="button"
            className="gh-btn-secondary min-h-9 px-3 py-1"
            disabled={busy}
            onClick={() => void run(`${base}/mute`, "POST", { minutes: m })}
          >
            {t(`mute.${m}`)}
          </button>
        ))}
        {rule.muted_until ? (
          <button
            type="button"
            className="gh-btn-secondary min-h-9 px-3 py-1"
            disabled={busy}
            onClick={() => void run(`${base}/mute`, "POST", { minutes: 0 })}
          >
            {t("unmute")}
          </button>
        ) : null}
      </div>
      <ErrorText error={error} />
    </form>
  );
}
