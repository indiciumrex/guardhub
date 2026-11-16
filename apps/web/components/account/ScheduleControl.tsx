"use client";
/**
 * Automatic scan schedule for one project (docs/architecture.md §8.2): Off / Daily / Weekly,
 * saved with PATCH /projects/{id} {"scan_frequency"}. Daily and weekly need a verified
 * project; when the backend paused the schedule because the ownership proof disappeared, a
 * banner explains how to resume (re-verify, then save the schedule again).
 */
import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { useFormatter, useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import type { Project, ScanFrequency, SchedulePausedReason } from "@/lib/types";
import { useErrorMessage } from "@/lib/use-error-message";
import { Alert } from "@/components/ui/Alert";

const FREQUENCIES: readonly ScanFrequency[] = ["off", "daily", "weekly"];

export interface ScheduleState {
  scan_frequency: ScanFrequency;
  next_scan_at: string | null;
  schedule_paused_reason: SchedulePausedReason | null;
}

interface ScheduleControlProps {
  projectId: string;
  verified: boolean;
  initial: ScheduleState;
}

export function ScheduleControl({ projectId, verified, initial }: ScheduleControlProps) {
  const t = useTranslations("schedule");
  const tCommon = useTranslations("common");
  const format = useFormatter();
  const router = useRouter();
  const errorMessage = useErrorMessage();
  const [saved, setSaved] = useState<ScheduleState>(initial);
  const [choice, setChoice] = useState<ScanFrequency>(initial.scan_frequency);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [justSaved, setJustSaved] = useState(false);

  const paused = saved.schedule_paused_reason === "ownership_lost";
  const needsProof = (frequency: ScanFrequency) => frequency !== "off" && !verified;
  // Saving the same frequency again is how a paused schedule resumes (§8.2).
  const canSave = !busy && !needsProof(choice) && (choice !== saved.scan_frequency || paused);
  const hintId = `schedule-hint-${projectId}`;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canSave) return;
    setBusy(true);
    setError(null);
    setJustSaved(false);
    try {
      const project = await apiFetch<Project>(`/projects/${encodeURIComponent(projectId)}`, {
        method: "PATCH",
        body: { scan_frequency: choice },
      });
      setSaved({
        scan_frequency: project.scan_frequency,
        next_scan_at: project.next_scan_at,
        schedule_paused_reason: project.schedule_paused_reason,
      });
      setChoice(project.scan_frequency);
      setJustSaved(true);
      router.refresh();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  let statusLine: string;
  if (saved.scan_frequency === "off") statusLine = t("currentOff");
  else if (saved.next_scan_at)
    statusLine = t("nextRun", {
      date: format.dateTime(new Date(saved.next_scan_at), {
        dateStyle: "medium",
        timeStyle: "short",
        timeZone: "UTC",
      }),
    });
  else statusLine = t("nextRunPending");

  return (
    <div className="space-y-4">
      {paused ? (
        <div
          role="status"
          className="rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-950 dark:border-amber-700 dark:bg-amber-950/50 dark:text-amber-100"
        >
          <p className="font-semibold">
            <span className="mr-2 inline-flex rounded-full border border-current px-2 py-0.5 text-xs">
              {t("pausedLabel")}
            </span>
            {t("pausedTitle")}
          </p>
          <p className="mt-1">{t("pausedBody")}</p>
          <p className="mt-1">{t("pausedSteps")}</p>
        </div>
      ) : (
        <p className="text-sm">{statusLine}</p>
      )}

      <form onSubmit={submit} className="space-y-4">
        <fieldset aria-describedby={verified ? undefined : hintId}>
          <legend className="gh-label">{t("legend")}</legend>
          <div className="mt-2 grid gap-2 sm:grid-cols-3">
            {FREQUENCIES.map((frequency) => {
              const disabled = busy || needsProof(frequency);
              const id = `schedule-${projectId}-${frequency}`;
              return (
                <div
                  key={frequency}
                  className={`flex items-start gap-3 rounded-lg border px-3 py-2 ${
                    choice === frequency
                      ? "border-teal-700 dark:border-teal-300"
                      : "border-slate-300 dark:border-navy-700"
                  } ${disabled ? "opacity-60" : ""}`}
                >
                  <input
                    type="radio"
                    id={id}
                    name={`schedule-${projectId}`}
                    value={frequency}
                    checked={choice === frequency}
                    disabled={disabled}
                    onChange={() => setChoice(frequency)}
                    aria-describedby={`${id}-hint`}
                    className="mt-1 h-4 w-4 accent-teal-700"
                  />
                  <label htmlFor={id} className="text-sm">
                    <span className="block font-semibold">{t(frequency)}</span>
                    <span id={`${id}-hint`} className="gh-muted block">
                      {t(`${frequency}Hint`)}
                    </span>
                  </label>
                </div>
              );
            })}
          </div>
        </fieldset>
        {!verified ? (
          <p id={hintId} className="gh-muted text-sm">
            {t("needsVerification")}
          </p>
        ) : null}
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
        <button type="submit" className="gh-btn-primary" disabled={!canSave}>
          {busy ? tCommon("working") : paused ? t("saveAndResume") : t("save")}
        </button>
      </form>
    </div>
  );
}
