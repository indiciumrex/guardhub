/**
 * "Compare with another scan": a plain GET form (works without JavaScript) that reloads the
 * compare page with `?against=<scanId>`. Offers only finished scans created before the scan
 * being viewed, newest first, which is what the API accepts (§8.3).
 */
import { useFormatter, useTranslations } from "next-intl";
import type { ScanSummary } from "@/lib/types";

interface CompareScanPickerProps {
  action: string;
  candidates: ScanSummary[];
  selectedId: string | null;
}

export function CompareScanPicker({ action, candidates, selectedId }: CompareScanPickerProps) {
  const t = useTranslations("compare");
  const tProject = useTranslations("project");
  const format = useFormatter();
  const newest = candidates[0];
  if (!newest) return null;
  return (
    <section aria-labelledby="compare-picker-heading" className="gh-card max-w-2xl p-5">
      <h2 id="compare-picker-heading" className="text-lg font-semibold">
        {t("pickerHeading")}
      </h2>
      <form method="get" action={action} className="mt-3 flex flex-wrap items-end gap-3">
        <div className="min-w-64 flex-1">
          <label htmlFor="compare-against" className="gh-label">
            {t("pickerLabel")}
          </label>
          <select
            id="compare-against"
            name="against"
            defaultValue={selectedId ?? newest.id}
            className="gh-input"
          >
            {candidates.map((scan) => (
              <option key={scan.id} value={scan.id}>
                {t("pickerOption", {
                  date: format.dateTime(new Date(scan.created_at), {
                    dateStyle: "medium",
                    timeStyle: "short",
                    timeZone: "UTC",
                  }),
                  score: scan.score ?? tProject("noScore"),
                })}
              </option>
            ))}
          </select>
        </div>
        <button type="submit" className="gh-btn-secondary">
          {t("pickerSubmit")}
        </button>
      </form>
    </section>
  );
}

/** Finished scans created before `scanId` in a newest-first history list. */
export function earlierDoneScans(scans: ScanSummary[], scanId: string): ScanSummary[] {
  const current = scans.find((scan) => scan.id === scanId);
  if (!current) return [];
  const createdAt = new Date(current.created_at).getTime();
  return scans.filter(
    (scan) =>
      scan.id !== scanId &&
      scan.status === "done" &&
      new Date(scan.created_at).getTime() < createdAt,
  );
}
