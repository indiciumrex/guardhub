"use client";
/**
 * Module configuration (PATCH /admin/modules/{key}/config): maintenance mode (kept out of new
 * scans without being switched off) and the minimum plan. Both changes are audited by the API.
 */
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import { PLANS, type CenterModule, type Plan } from "@/lib/admin-types";
import { useErrorMessage } from "@/lib/use-error-message";

export function ModuleConfig({ module }: { module: CenterModule }) {
  const t = useTranslations("adminCenter.modules");
  const errorMessage = useErrorMessage();
  const router = useRouter();
  const [maintenance, setMaintenance] = useState(module.maintenance);
  const [plan, setPlan] = useState<Plan>(module.min_plan);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function save(body: { maintenance?: boolean; min_plan?: Plan }) {
    setBusy(true);
    setError(null);
    try {
      const updated = await apiFetch<CenterModule>(
        `/admin/modules/${encodeURIComponent(module.key)}/config`,
        { method: "PATCH", body },
      );
      setMaintenance(updated.maintenance);
      setPlan(updated.min_plan);
      router.refresh();
    } catch (err) {
      setMaintenance(module.maintenance);
      setPlan(module.min_plan);
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const planId = `plan-${module.key}`;
  return (
    <div className="flex flex-col items-start gap-2 text-sm">
      <label className="inline-flex min-h-11 items-center gap-2">
        <input
          type="checkbox"
          checked={maintenance}
          disabled={busy}
          onChange={(e) => {
            setMaintenance(e.target.checked);
            void save({ maintenance: e.target.checked });
          }}
          className="h-4 w-4"
        />
        {t("maintenance")}
      </label>
      <div className="flex items-center gap-2">
        <label htmlFor={planId}>{t("plan")}</label>
        <select
          id={planId}
          value={plan}
          disabled={busy}
          onChange={(e) => {
            const next = e.target.value as Plan;
            setPlan(next);
            void save({ min_plan: next });
          }}
          className="gh-input min-h-9 w-auto min-w-28 py-1"
        >
          {PLANS.map((p) => (
            <option key={p} value={p}>
              {t(`plans.${p}`)}
            </option>
          ))}
        </select>
      </div>
      {error ? (
        <p role="alert" className="text-xs text-red-800 dark:text-red-200">
          {error}
        </p>
      ) : null}
    </div>
  );
}
