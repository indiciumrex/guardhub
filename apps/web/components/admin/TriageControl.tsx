"use client";
/**
 * The admin's verdict on one finding group (PUT /admin/findings/{fingerprint}/triage): verified,
 * accepted risk, false positive or resolved, with an optional note. Audited (finding.triage);
 * false positives feed the module's production false-positive rate in the Module Center.
 */
import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import type { FindingGroup, TriageStatus } from "@/lib/admin-types";
import { useErrorMessage } from "@/lib/use-error-message";

const CHOICES: Exclude<TriageStatus, "new">[] = [
  "verified",
  "accepted",
  "false_positive",
  "resolved",
];

export function TriageControl({ group }: { group: FindingGroup }) {
  const t = useTranslations("adminCenter.findings");
  const errorMessage = useErrorMessage();
  const router = useRouter();
  const [status, setStatus] = useState<Exclude<TriageStatus, "new">>(
    group.triage === "new" ? "verified" : group.triage,
  );
  const [note, setNote] = useState(group.triage_note);
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      await apiFetch(`/admin/findings/${encodeURIComponent(group.fingerprint)}/triage`, {
        method: "PUT",
        body: { status, note },
      });
      setSaved(true);
      router.refresh();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const id = group.fingerprint.slice(0, 12);
  return (
    <form onSubmit={submit} className="flex min-w-56 flex-col gap-2 text-sm">
      <label htmlFor={`triage-${id}`} className="sr-only">
        {t("triageLabel")}
      </label>
      <select
        id={`triage-${id}`}
        value={status}
        onChange={(e) => setStatus(e.target.value as Exclude<TriageStatus, "new">)}
        className="gh-input min-h-9 py-1"
      >
        {CHOICES.map((c) => (
          <option key={c} value={c}>
            {t(`triage.${c}`)}
          </option>
        ))}
      </select>
      <label htmlFor={`note-${id}`} className="sr-only">
        {t("noteLabel")}
      </label>
      <input
        id={`note-${id}`}
        value={note}
        maxLength={500}
        placeholder={t("notePlaceholder")}
        onChange={(e) => setNote(e.target.value)}
        className="gh-input min-h-9 py-1"
      />
      <button type="submit" className="gh-btn gh-btn-secondary min-h-9 px-3 py-1" disabled={busy}>
        {t("save")}
      </button>
      {saved ? <p role="status">{t("saved")}</p> : null}
      {error ? (
        <p role="alert" className="text-xs text-red-800 dark:text-red-200">
          {error}
        </p>
      ) : null}
    </form>
  );
}
