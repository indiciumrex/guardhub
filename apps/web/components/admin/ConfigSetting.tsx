"use client";
/**
 * One runtime setting (PUT /admin/config/settings/{key}, POST .../reset): a switch for flags, a
 * bounded number or a short text. The API validates the bounds again and audits every change;
 * the optional reason goes into the change history.
 */
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import type { ConfigSetting as Setting, SettingValue } from "@/lib/admin-types";
import { useErrorMessage } from "@/lib/use-error-message";

export function ConfigSetting({ setting, label }: { setting: Setting; label: string }) {
  const t = useTranslations("adminCenter.config");
  const errorMessage = useErrorMessage();
  const router = useRouter();
  const [draft, setDraft] = useState<string>(String(setting.value));
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const id = `setting-${setting.key.replace(/\./g, "-")}`;

  async function send(path: string, method: "PUT" | "POST", body: object) {
    setBusy(true);
    setError(null);
    try {
      const updated = await apiFetch<Setting>(path, { method, body });
      setDraft(String(updated.value));
      setReason("");
      router.refresh();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }
  const path = `/admin/config/settings/${encodeURIComponent(setting.key)}`;
  const save = (value: SettingValue) => send(path, "PUT", { value, reason });
  const reset = () => send(`${path}/reset`, "POST", { reason });

  const changed = draft !== String(setting.value);
  const parsed = setting.kind === "int" ? Number(draft) : draft;
  const valid =
    setting.kind !== "int" ||
    (Number.isInteger(parsed) &&
      (setting.minimum === null || (parsed as number) >= setting.minimum) &&
      (setting.maximum === null || (parsed as number) <= setting.maximum));

  return (
    <div className="space-y-2">
      {setting.kind === "bool" ? (
        <label className="inline-flex min-h-11 items-center gap-3 text-sm font-medium">
          <input
            id={id}
            type="checkbox"
            role="switch"
            aria-checked={setting.value === true}
            checked={setting.value === true}
            disabled={busy}
            onChange={(e) => void save(e.target.checked)}
            className="h-5 w-5"
          />
          {label}
        </label>
      ) : (
        <div className="flex flex-wrap items-end gap-2">
          <div className="min-w-0 grow">
            <label htmlFor={id} className="block text-sm font-medium">
              {label}
            </label>
            <input
              id={id}
              type={setting.kind === "int" ? "number" : "text"}
              inputMode={setting.kind === "int" ? "numeric" : undefined}
              min={setting.minimum ?? undefined}
              max={setting.maximum ?? undefined}
              maxLength={setting.max_length ?? undefined}
              value={draft}
              disabled={busy}
              aria-describedby={`${id}-range`}
              onChange={(e) => setDraft(e.target.value)}
              className={`gh-input mt-1 py-1.5 ${setting.kind === "int" ? "w-32" : "w-full"}`}
            />
          </div>
          <button
            type="button"
            className="gh-btn-primary min-h-9 px-3 py-1.5 text-sm"
            disabled={busy || !changed || !valid}
            onClick={() => void save(setting.kind === "int" ? Number(draft) : draft)}
          >
            {t("save")}
          </button>
        </div>
      )}
      <p id={`${id}-range`} className="gh-muted text-xs">
        {setting.kind === "int"
          ? t("range", { min: setting.minimum ?? "-", max: setting.maximum ?? "-" })
          : null}
        {setting.kind === "int" ? " · " : null}
        {t("defaultIs", { value: formatValue(setting.default, t) })}
      </p>
      <div className="flex flex-wrap items-center gap-2">
        <label htmlFor={`${id}-reason`} className="sr-only">
          {t("reason")}
        </label>
        <input
          id={`${id}-reason`}
          type="text"
          maxLength={200}
          placeholder={t("reasonPlaceholder")}
          value={reason}
          disabled={busy}
          onChange={(e) => setReason(e.target.value)}
          className="gh-input min-w-0 grow py-1 text-xs"
        />
        {setting.overridden ? (
          <button
            type="button"
            className="gh-btn-secondary min-h-9 px-3 py-1 text-xs"
            disabled={busy}
            onClick={() => void reset()}
          >
            {t("resetToDefault")}
          </button>
        ) : null}
      </div>
      {error ? (
        <p role="alert" className="text-xs text-red-800 dark:text-red-200">
          {error}
        </p>
      ) : null}
    </div>
  );
}

export function formatValue(
  v: SettingValue | string,
  t: (key: "on" | "off" | "empty") => string,
): string {
  if (v === true || v === "true") return t("on");
  if (v === false || v === "false") return t("off");
  if (v === "" || v === '""') return t("empty");
  return String(v);
}

export function ConfigRevert({ changeId }: { changeId: number }) {
  const t = useTranslations("adminCenter.config");
  const errorMessage = useErrorMessage();
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <span className="inline-flex flex-col items-start gap-1">
      <button
        type="button"
        className="gh-btn-secondary min-h-9 px-3 py-1 text-xs"
        disabled={busy}
        onClick={async () => {
          setBusy(true);
          setError(null);
          try {
            await apiFetch(`/admin/config/history/${changeId}/revert`, { method: "POST" });
            router.refresh();
          } catch (err) {
            setError(errorMessage(err));
          } finally {
            setBusy(false);
          }
        }}
      >
        {t("revert")}
      </button>
      {error ? (
        <span role="alert" className="text-xs text-red-800 dark:text-red-200">
          {error}
        </span>
      ) : null}
    </span>
  );
}
