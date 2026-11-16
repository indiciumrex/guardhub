"use client";
/**
 * Accessible on/off switch for a module's global flag (PATCH /admin/modules/{key}).
 * role="switch" + aria-checked, keyboard-operable (Space/Enter on a button), visible "On/Off".
 */
import { useState } from "react";
import { useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import type { AdminModule } from "@/lib/types";
import { useErrorMessage } from "@/lib/use-error-message";

export function ModuleToggle({ module }: { module: AdminModule }) {
  const t = useTranslations("admin");
  const errorMessage = useErrorMessage();
  const [enabled, setEnabled] = useState(module.enabled_global);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function toggle() {
    const nextValue = !enabled;
    setBusy(true);
    setError(null);
    setEnabled(nextValue); // optimistic
    try {
      const updated = await apiFetch<AdminModule>(
        `/admin/modules/${encodeURIComponent(module.key)}`,
        {
          method: "PATCH",
          body: { enabled_global: nextValue },
        },
      );
      setEnabled(updated.enabled_global);
    } catch (err) {
      setEnabled(!nextValue);
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col items-start gap-1">
      <button
        type="button"
        role="switch"
        aria-checked={enabled}
        aria-label={t("toggleLabel", { name: module.name })}
        disabled={busy}
        onClick={toggle}
        className="inline-flex min-h-11 items-center gap-2 rounded-full disabled:opacity-60"
      >
        <span
          aria-hidden="true"
          className={`relative inline-flex h-6 w-11 items-center rounded-full border transition-colors ${
            enabled
              ? "border-teal-700 bg-teal-700 dark:border-teal-300 dark:bg-teal-300"
              : "border-slate-400 bg-slate-200 dark:border-navy-600 dark:bg-navy-800"
          }`}
        >
          <span
            className={`inline-block h-4 w-4 rounded-full bg-white shadow transition-transform dark:bg-navy-950 ${
              enabled ? "translate-x-6" : "translate-x-1"
            }`}
          />
        </span>
        <span className="text-sm font-semibold">{enabled ? t("on") : t("off")}</span>
      </button>
      {error ? (
        <p role="alert" className="text-xs text-red-800 dark:text-red-200">
          {error}
        </p>
      ) : null}
    </div>
  );
}
