/**
 * Alert history (GET /account/notifications/history, §8.4): when, which project, which
 * channel, what happened, delivery status (as text), and a link to the details.
 * Rows: scan changes (link to the comparison), "monitoring paused" (link to the project) and
 * test messages (marked "Test"; hidden unless the "Tests"/"All" filter is chosen).
 */
import Link from "next/link";
import { useFormatter, useTranslations } from "next-intl";
import type {
  NotificationHistoryFilter,
  NotificationHistoryItem,
  NotificationStatus,
} from "@/lib/types";

const statusClasses: Record<NotificationStatus, string> = {
  pending: "border-slate-300 text-slate-700 dark:border-slate-600 dark:text-slate-200",
  sent: "border-emerald-300 text-emerald-800 dark:border-emerald-700 dark:text-emerald-200",
  failed: "border-red-300 text-red-800 dark:border-red-700 dark:text-red-200",
  skipped: "border-amber-300 text-amber-900 dark:border-amber-700 dark:text-amber-200",
};

const FILTERS: NotificationHistoryFilter[] = ["alerts", "test", "all"];

/** Server-rendered filter links (no client state): the URL is the filter. */
export function NotificationHistoryFilters({ active }: { active: NotificationHistoryFilter }) {
  const t = useTranslations("notifications");
  return (
    <nav aria-label={t("historyFilterLabel")} className="flex flex-wrap items-center gap-2 text-sm">
      <span className="gh-muted" aria-hidden="true">
        {t("historyFilterLabel")}:
      </span>
      {FILTERS.map((filter) => {
        const current = filter === active;
        return (
          <Link
            key={filter}
            href={
              filter === "alerts"
                ? "/account/notifications#alert-history-heading"
                : `/account/notifications?show=${filter}#alert-history-heading`
            }
            aria-current={current ? "page" : undefined}
            className={`rounded-full border px-3 py-1 font-medium ${
              current
                ? "border-slate-900 bg-slate-900 text-white dark:border-slate-100 dark:bg-slate-100 dark:text-slate-900"
                : "border-slate-300 dark:border-slate-600"
            }`}
          >
            {t(`historyFilter.${filter}`)}
          </Link>
        );
      })}
    </nav>
  );
}

export function NotificationHistory({
  items,
  projectNames,
  filter = "alerts",
}: {
  items: NotificationHistoryItem[];
  projectNames: Record<string, string>;
  filter?: NotificationHistoryFilter;
}) {
  const t = useTranslations("notifications");
  const format = useFormatter();
  const formatDate = (value: string) =>
    format.dateTime(new Date(value), { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" });

  if (items.length === 0) {
    return <p className="gh-muted">{t(filter === "test" ? "historyEmptyTest" : "historyEmpty")}</p>;
  }

  return (
    <div className="gh-card overflow-x-auto">
      <table className="gh-table">
        <caption className="sr-only">{t("historyCaption")}</caption>
        <thead>
          <tr>
            <th scope="col">{t("colDate")}</th>
            <th scope="col">{t("colProject")}</th>
            <th scope="col">{t("colChannel")}</th>
            <th scope="col">{t("colChanges")}</th>
            <th scope="col">{t("colStatus")}</th>
            <th scope="col">
              <span className="sr-only">{t("colDetails")}</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => {
            const projectName = item.project_id ? projectNames[item.project_id] : undefined;
            const when = formatDate(item.created_at);
            return (
              <tr key={item.id}>
                <td className="whitespace-nowrap">{when}</td>
                <td>
                  {item.kind === "test" ? (
                    <span className="gh-muted">-</span>
                  ) : (
                    (projectName ?? <span className="gh-muted">{t("unknownProject")}</span>)
                  )}
                </td>
                <td>{t(`channel.${item.channel}`)}</td>
                <td>
                  {item.kind === "scan_change" ? (
                    t("changes", {
                      new: item.new_count,
                      regressed: item.regression_count,
                      fixed: item.fixed_count,
                    })
                  ) : (
                    <span className="inline-flex flex-wrap items-center gap-2">
                      {item.kind === "test" ? (
                        <span className="inline-flex rounded border border-slate-400 px-1.5 text-xs font-semibold uppercase tracking-wide text-slate-700 dark:border-slate-500 dark:text-slate-200">
                          {t("testBadge")}
                        </span>
                      ) : null}
                      {t(`kind.${item.kind}`)}
                    </span>
                  )}
                </td>
                <td>
                  <span
                    className={`inline-flex rounded-full border px-2.5 py-0.5 text-xs font-semibold ${statusClasses[item.status]}`}
                  >
                    {t(`status.${item.status}`)}
                  </span>
                </td>
                <td>
                  <DetailsLink item={item} projectName={projectName} when={when} />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function DetailsLink({
  item,
  projectName,
  when,
}: {
  item: NotificationHistoryItem;
  projectName: string | undefined;
  when: string;
}) {
  const t = useTranslations("notifications");
  if (!item.project_id || !projectName) return null; // tests, deleted projects
  const project = `/account/projects/${encodeURIComponent(item.project_id)}`;
  const [href, label] =
    item.kind === "scan_change" && item.scan_id
      ? [`${project}/compare/${encodeURIComponent(item.scan_id)}`, t("viewChanges")]
      : [project, t("openProject")];
  return (
    <Link href={href} className="gh-link whitespace-nowrap">
      {label}
      <span className="sr-only">
        {" "}
        {projectName}, {when}
      </span>
    </Link>
  );
}
