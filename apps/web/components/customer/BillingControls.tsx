"use client";
/**
 * Billing controls (Phase 5C): the customer's trial button, and the admin's plan limits editor
 * and plan assignment. Charging (taking money) is not offered here until the founder turns it
 * on; the API refuses it anyway.
 */
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import type { PlanLimits } from "@/lib/admin-types";
import { useErrorMessage } from "@/lib/use-error-message";

function useAction() {
  const errorMessage = useErrorMessage();
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function run(path: string, method: "POST" | "PUT", body: object): Promise<boolean> {
    setBusy(true);
    setError(null);
    try {
      await apiFetch(path, { method, body });
      router.refresh();
      return true;
    } catch (err) {
      setError(errorMessage(err));
      return false;
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

export function StartTrial({ plan, days, label }: { plan: string; days: number; label: string }) {
  const t = useTranslations("billing");
  const { busy, error, run } = useAction();
  return (
    <div className="space-y-1">
      <button
        type="button"
        className="gh-btn-primary min-h-9 px-3 py-1.5 text-sm"
        aria-label={t("trialNamed", { plan: label, days })}
        disabled={busy}
        onClick={() => void run("/billing/trial", "POST", { plan })}
      >
        {t("startTrial", { days })}
      </button>
      <ErrorText error={error} />
    </div>
  );
}

export function PlanEditor({ plan, label }: { plan: PlanLimits; label: string }) {
  const t = useTranslations("billing.admin");
  const { busy, error, run } = useAction();
  const [v, setV] = useState({
    max_sites: plan.max_sites,
    scans_per_day: plan.scans_per_day,
    concurrent_scans: plan.concurrent_scans,
    trial_days: plan.trial_days,
    public: plan.public,
  });
  const field = (
    k: "max_sites" | "scans_per_day" | "concurrent_scans" | "trial_days",
    max: number,
  ) => (
    <div key={k}>
      <label htmlFor={`${plan.key}-${k}`} className="block text-xs">
        {t(`field.${k}`)}
      </label>
      <input
        id={`${plan.key}-${k}`}
        type="number"
        min={k === "trial_days" ? 0 : 1}
        max={max}
        value={v[k]}
        disabled={busy || (k === "trial_days" && plan.key === "free")}
        onChange={(e) => setV({ ...v, [k]: Number(e.target.value) })}
        className="gh-input mt-1 w-24 py-1 text-sm"
      />
    </div>
  );
  return (
    <form
      aria-label={label}
      className="flex flex-wrap items-end gap-3"
      onSubmit={(e) => {
        e.preventDefault();
        void run(`/admin/billing/plans/${plan.key}`, "PUT", v);
      }}
    >
      {field("max_sites", 1000)}
      {field("scans_per_day", 10000)}
      {field("concurrent_scans", 100)}
      {field("trial_days", 90)}
      <label className="inline-flex min-h-9 items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={v.public}
          disabled={busy || plan.key === "free"}
          onChange={(e) => setV({ ...v, public: e.target.checked })}
          className="h-4 w-4"
        />
        {t("public")}
      </label>
      <button type="submit" className="gh-btn-primary min-h-9 px-3 py-1.5 text-sm" disabled={busy}>
        {t("save")}
      </button>
      <ErrorText error={error} />
    </form>
  );
}

export function AssignPlan() {
  const t = useTranslations("billing.admin");
  const tp = useTranslations("billing.plan");
  const { busy, error, run } = useAction();
  const [email, setEmail] = useState("");
  const [plan, setPlan] = useState("pro");
  const [reason, setReason] = useState("");
  return (
    <form
      aria-label={t("assignTitle")}
      className="flex flex-wrap items-end gap-3 text-sm"
      onSubmit={async (e) => {
        e.preventDefault();
        if (
          await run("/admin/billing/subscriptions", "POST", {
            email: email.trim(),
            plan,
            reason: reason.trim(),
          })
        ) {
          setEmail("");
          setReason("");
        }
      }}
    >
      <div>
        <label htmlFor="assign-email" className="block">
          {t("email")}
        </label>
        <input
          id="assign-email"
          type="email"
          value={email}
          disabled={busy}
          onChange={(e) => setEmail(e.target.value)}
          className="gh-input mt-1 w-56 py-1.5"
        />
      </div>
      <div>
        <label htmlFor="assign-plan" className="block">
          {t("planLabel")}
        </label>
        <select
          id="assign-plan"
          value={plan}
          disabled={busy}
          onChange={(e) => setPlan(e.target.value)}
          className="gh-input mt-1 w-auto min-w-28 py-1.5"
        >
          {(["free", "pro", "agency"] as const).map((k) => (
            <option key={k} value={k}>
              {tp(k)}
            </option>
          ))}
        </select>
      </div>
      <div>
        <label htmlFor="assign-reason" className="block">
          {t("reason")}
        </label>
        <input
          id="assign-reason"
          value={reason}
          maxLength={200}
          disabled={busy}
          onChange={(e) => setReason(e.target.value)}
          className="gh-input mt-1 w-56 py-1.5"
        />
      </div>
      <button
        type="submit"
        className="gh-btn-primary min-h-9 px-3 py-1.5"
        disabled={busy || !email.includes("@") || reason.trim().length < 3}
      >
        {t("assign")}
      </button>
      <ErrorText error={error} />
    </form>
  );
}
