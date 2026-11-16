/**
 * Alert history (GET /account/notifications/history, §8.4): when, which project, which
 * channel, what changed, delivery status (as text), and a link to the changes.
 */
import Link from "next/link";
import { useFormatter, useTranslations } from "next-intl";
import type { NotificationHistoryItem, NotificationStatus } from "@/lib/types";

const statusClasses: Record<NotificationStatus, string> = {
  pending: "border-slate-300 text-slate-700 dark:border-slate-600 dark:text-slate-200",
  sent: "border-emerald-300 text-emerald-800 dark:border-emerald-700 dark:text-emerald-200",
  failed: "border-red-300 text-red-800 dark:border-red-700 dark:text-red-200",
  skipped: "border-amber-300 text-amber-900 dark:border-amber-700 dark:text-amber-200",
};

export function NotificationHistory({
  items,
  projectNames,
}: {
  items: NotificationHistoryItem[];
  projectNames: Record<string, string>;
}) {
  const t = useTranslations("notifications");
  const format = useFormatter();
  const formatDate = (value: string) =>
    format.dateTime(new Date(value), { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" });

  if (items.length === 0) return <p className="gh-muted">{t("historyEmpty")}</p>;

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
            return (
              <tr key={item.id}>
                <td className="whitespace-nowrap">{formatDate(item.created_at)}</td>
                <td>{projectName ?? <span className="gh-muted">{t("unknownProject")}</span>}</td>
                <td>{t(`channel.${item.channel}`)}</td>
                <td>
                  {t("changes", {
                    new: item.new_count,
                    regressed: item.regression_count,
                    fixed: item.fixed_count,
                  })}
                </td>
                <td>
                  <span
                    className={`inline-flex rounded-full border px-2.5 py-0.5 text-xs font-semibold ${statusClasses[item.status]}`}
                  >
                    {t(`status.${item.status}`)}
                  </span>
                </td>
                <td>
                  {item.project_id && projectName ? (
                    <Link
                      href={`/account/projects/${encodeURIComponent(item.project_id)}/compare/${encodeURIComponent(item.scan_id)}`}
                      className="gh-link whitespace-nowrap"
                    >
                      {t("viewChanges")}
                      <span className="sr-only">
                        {" "}
                        {projectName}, {formatDate(item.created_at)}
                      </span>
                    </Link>
                  ) : null}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
