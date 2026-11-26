"use client";
/**
 * Super-admin observe-only scan (profile prompt item 3): a passive look at a site without an
 * ownership proof. Only observe-only checks; the authorisation statement, the relationship and a
 * note are mandatory and recorded. Everything that probes, injects or signs in needs a verified
 * site and is not offered here.
 */
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import type { ObserveReadiness } from "@/lib/admin-types";
import type { ScanSummary } from "@/lib/types";
import { useErrorMessage } from "@/lib/use-error-message";

const RELATIONSHIPS = ["owner", "client", "employer", "other"] as const;

export function ObserveScanForm({ readiness }: { readiness: ObserveReadiness }) {
  const t = useTranslations("observe");
  const tChecks = useTranslations("checks");
  const errorMessage = useErrorMessage();
  const router = useRouter();
  const [target, setTarget] = useState("");
  const [relationship, setRelationship] = useState<(typeof RELATIONSHIPS)[number]>("client");
  const [note, setNote] = useState("");
  const [accepted, setAccepted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const disabled = !readiness.enabled;

  return (
    <form
      aria-label={t("formLabel")}
      className="grid max-w-2xl gap-4 text-sm"
      onSubmit={async (e) => {
        e.preventDefault();
        setBusy(true);
        setError(null);
        try {
          const scan = await apiFetch<ScanSummary>("/admin/observe-scans", {
            method: "POST",
            body: {
              target_url: target.trim(),
              relationship,
              note: note.trim(),
              statement_version: readiness.statement_version,
              accept_statement: accepted,
            },
          });
          router.push(`/account/scans/${scan.id}`);
        } catch (err) {
          setError(errorMessage(err));
          setBusy(false);
        }
      }}
    >
      <fieldset disabled={disabled} className="grid gap-4">
        <div>
          <label htmlFor="observe-target" className="gh-label">
            {t("targetLabel")}
          </label>
          <input
            id="observe-target"
            inputMode="url"
            spellCheck={false}
            maxLength={2048}
            placeholder="example.com"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            className="gh-input w-full"
            required
          />
        </div>
        <div>
          <label htmlFor="observe-relationship" className="gh-label">
            {t("relationshipLabel")}
          </label>
          <select
            id="observe-relationship"
            value={relationship}
            onChange={(e) => setRelationship(e.target.value as (typeof RELATIONSHIPS)[number])}
            className="gh-input"
          >
            {RELATIONSHIPS.map((r) => (
              <option key={r} value={r}>
                {t(`relationship.${r}`)}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor="observe-note" className="gh-label">
            {t("noteLabel")}
          </label>
          <textarea
            id="observe-note"
            rows={3}
            minLength={10}
            maxLength={500}
            value={note}
            onChange={(e) => setNote(e.target.value)}
            className="gh-input w-full"
            aria-describedby="observe-note-help"
            required
          />
          <p id="observe-note-help" className="gh-muted mt-1 text-xs">
            {t("noteHelp")}
          </p>
        </div>
        <div className="gh-tone-warn rounded-lg border p-3">
          <p className="font-semibold">{t("statementTitle")}</p>
          <p className="mt-1">{readiness.statement}</p>
          <label className="mt-2 flex items-start gap-2">
            <input
              type="checkbox"
              checked={accepted}
              onChange={(e) => setAccepted(e.target.checked)}
              className="mt-1 h-4 w-4"
            />
            <span>{t("accept", { version: readiness.statement_version })}</span>
          </label>
        </div>
        <div>
          <p className="font-medium">{t("runs")}</p>
          <p className="gh-muted mt-1">
            {readiness.checks
              .map((c) => (tChecks.has(`${c}.name`) ? tChecks(`${c}.name`) : c))
              .join(" · ")}
          </p>
        </div>
        <div>
          <button
            type="submit"
            className="gh-btn-primary"
            disabled={busy || !accepted || note.trim().length < 10 || !target.trim()}
          >
            {t("start")}
          </button>
        </div>
      </fieldset>
      {error ? (
        <p role="alert" className="text-red-800 dark:text-red-200">
          {error}
        </p>
      ) : null}
    </form>
  );
}
