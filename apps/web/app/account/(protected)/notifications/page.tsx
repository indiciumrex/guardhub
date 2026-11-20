/**
 * Alerts page (§8.4): alert settings (e-mail, which changes, write-only Slack webhook),
 * "Send test" per channel, and the recent alert history. The history shows real alerts by
 * default; test messages only with ?show=test (or ?show=all), so they never clutter it.
 */
import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import {
  NotificationHistory,
  NotificationHistoryFilters,
} from "@/components/account/NotificationHistory";
import { NotificationSettingsForm } from "@/components/account/NotificationSettingsForm";
import { NotificationTestButtons } from "@/components/account/NotificationTestButtons";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import type {
  NotificationHistoryFilter,
  NotificationHistoryItem,
  NotificationSettings,
  Project,
} from "@/lib/types";

const HISTORY_LIMIT = 20;

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("notifications");
  return { title: t("metaTitle") };
}

function historyFilter(value: string | string[] | undefined): NotificationHistoryFilter {
  return value === "test" || value === "all" ? value : "alerts";
}

export default async function NotificationsPage({
  searchParams,
}: {
  searchParams: Promise<{ show?: string | string[] }>;
}) {
  const show = historyFilter((await searchParams).show);
  const [settings, history, projects] = await loadProtected(() =>
    Promise.all([
      serverApiFetch<NotificationSettings>("/account/notifications"),
      serverApiFetch<NotificationHistoryItem[]>("/account/notifications/history", {
        query: { limit: HISTORY_LIMIT, show },
      }),
      serverApiFetch<Project[]>("/projects"),
    ]),
  );
  const t = await getTranslations("notifications");
  const projectNames = Object.fromEntries(projects.map((project) => [project.id, project.name]));

  return (
    <div className="max-w-4xl space-y-10">
      <div>
        <h1 className="text-3xl font-bold">{t("title")}</h1>
        <p className="gh-muted mt-2">{t("intro")}</p>
      </div>

      <section aria-labelledby="alert-settings-heading" className="gh-card max-w-2xl p-6">
        <h2 id="alert-settings-heading" className="text-xl font-semibold">
          {t("settingsHeading")}
        </h2>
        <div className="mt-4">
          <NotificationSettingsForm initial={settings} />
        </div>
      </section>

      <section aria-labelledby="alert-test-heading" className="space-y-3">
        <h2 id="alert-test-heading" className="text-xl font-semibold">
          {t("testHeading")}
        </h2>
        <p className="gh-muted text-sm">{t("testIntro")}</p>
        <NotificationTestButtons slackConfigured={settings.slack_configured} />
      </section>

      <section aria-labelledby="alert-history-heading" className="space-y-4">
        <h2 id="alert-history-heading" className="text-xl font-semibold">
          {t("historyHeading")}
        </h2>
        <NotificationHistoryFilters active={show} />
        <NotificationHistory items={history} projectNames={projectNames} filter={show} />
      </section>
    </div>
  );
}
