/**
 * Visible scan (§8.2): each check as a live row "queued → running → done/failed". Status is
 * text + icon (not colour alone); a polite live region announces overall progress.
 */
import { useTranslations } from "next-intl";
import type { CheckRunStatus, ProgressItem } from "@/lib/types";

const statusClasses: Record<CheckRunStatus, string> = {
  queued: "text-slate-600 dark:text-slate-300",
  running: "text-sky-800 dark:text-sky-200",
  done: "text-emerald-800 dark:text-emerald-200",
  failed: "text-red-800 dark:text-red-200",
};

function StatusIcon({ status }: { status: CheckRunStatus }) {
  if (status === "running") {
    return (
      <svg
        viewBox="0 0 20 20"
        className="h-5 w-5 animate-spin"
        aria-hidden="true"
        focusable="false"
      >
        <circle
          cx="10"
          cy="10"
          r="7"
          fill="none"
          stroke="currentColor"
          strokeOpacity="0.25"
          strokeWidth="2.5"
        />
        <path
          d="M10 3a7 7 0 0 1 7 7"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.5"
          strokeLinecap="round"
        />
      </svg>
    );
  }
  const paths: Record<Exclude<CheckRunStatus, "running">, string> = {
    queued:
      "M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14Zm0 2a5 5 0 1 1 0 10 5 5 0 0 1 0-10Zm-1 1.5V10l3 2 .9-1.4-1.9-1.3V6.5H9Z",
    done: "M10 2a8 8 0 1 0 0 16 8 8 0 0 0 0-16Zm-1.2 11.4L5.3 9.9l1.4-1.4 2.1 2.1 4.5-4.5 1.4 1.4-5.9 5.9Z",
    failed:
      "M10 2a8 8 0 1 0 0 16 8 8 0 0 0 0-16ZM7.2 5.8 10 8.6l2.8-2.8 1.4 1.4-2.8 2.8 2.8 2.8-1.4 1.4-2.8-2.8-2.8 2.8-1.4-1.4 2.8-2.8-2.8-2.8 1.4-1.4Z",
  };
  return (
    <svg viewBox="0 0 20 20" className="h-5 w-5" aria-hidden="true" focusable="false">
      <path fill="currentColor" fillRule="evenodd" d={paths[status]} />
    </svg>
  );
}

export function ProgressList({ items }: { items: ProgressItem[] }) {
  const t = useTranslations("progress");
  const tChecks = useTranslations("checks");
  const finished = items.filter(
    (item) => item.status === "done" || item.status === "failed",
  ).length;
  const running = items.find((item) => item.status === "running");
  const nameOf = (item: ProgressItem) =>
    item.name ||
    (tChecks.has(`${item.check_id}.name`) ? tChecks(`${item.check_id}.name`) : item.check_id);

  return (
    <section aria-labelledby="progress-heading" className="gh-card p-5 sm:p-6">
      <h2 id="progress-heading" className="text-lg font-semibold">
        {t("heading")}
      </h2>
      <p aria-live="polite" aria-atomic="true" className="gh-muted mt-1 text-sm">
        {t("summary", { done: finished, total: items.length })}
        {running ? ` ${t("nowRunning", { name: nameOf(running) })}` : ""}
      </p>
      {items.length === 0 ? (
        <p className="gh-muted mt-4 text-sm">{t("waiting")}</p>
      ) : (
        <ol
          className="mt-4 divide-y divide-slate-100 dark:divide-navy-800"
          aria-busy={finished < items.length}
        >
          {items.map((item) => (
            <li key={item.check_id} className="flex items-center justify-between gap-3 py-3">
              <span className="font-medium">{nameOf(item)}</span>
              <span
                className={`inline-flex items-center gap-2 text-sm font-semibold ${statusClasses[item.status]}`}
                data-status={item.status}
              >
                <StatusIcon status={item.status} />
                {t(`status.${item.status}`)}
              </span>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
