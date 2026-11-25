/**
 * Configuration & feature flags (Admin Panel, Prompt 2 §1).
 *
 * Order matters: the read-only safety status and what can NOT be changed here come first, then
 * maintenance mode, feature flags, scan and concurrency limits, rate limits, the environment
 * (secrets only as configured / not set) and the change history with revert.
 * Nothing on this page can reach the four active-testing locks or ownership proof (§9.2).
 */
import type { Metadata } from "next";
import Link from "next/link";
import { getFormatter, getTranslations } from "next-intl/server";
import { ConfigRevert, ConfigSetting, formatValue } from "@/components/admin/ConfigSetting";
import { SafetyStatus } from "@/components/admin/SafetyStatus";
import { HashId, PageHeader, Panel, StatusBadge } from "@/components/admin/Stat";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import type {
  CenterModule,
  ConfigSetting as Setting,
  ConfigView,
  ModuleStats,
  Orchestration,
} from "@/lib/admin-types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("adminCenter.config");
  return { title: t("title") };
}

function settled<T>(result: PromiseSettledResult<T>): T | null {
  return result.status === "fulfilled" ? result.value : null;
}

const FIXED = ["activeLocks", "killSwitch", "ownership", "auth", "secrets"] as const;

export default async function AdminConfigPage() {
  const [configR, orchR, modulesR, statsR] = await loadProtected(() =>
    Promise.allSettled([
      serverApiFetch<ConfigView>("/admin/config"),
      serverApiFetch<Orchestration>("/admin/orchestration"),
      serverApiFetch<CenterModule[]>("/admin/modules"),
      serverApiFetch<ModuleStats[]>("/admin/modules/stats"),
    ]),
  );
  const config = settled(configR);
  const t = await getTranslations("adminCenter.config");
  const tConsole = await getTranslations("adminCenter.console");
  const tAdmin = await getTranslations("admin");
  const format = await getFormatter();
  const when = (v: string | null) =>
    v
      ? format.dateTime(new Date(v), { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" })
      : "-";
  // message keys cannot contain dots (next-intl reads them as nesting): maintenance.enabled -> maintenance_enabled
  const label = (key: string) => {
    const k = `keys.${key.replace(/\./g, "_")}`;
    return t.has(k) ? t(k) : key;
  };
  const shown = (raw: string) => {
    if (raw === "__default__") return t("defaultValue");
    try {
      return formatValue(JSON.parse(raw) as string | number | boolean, t);
    } catch {
      return raw;
    }
  };

  const group = (g: Setting["group"]) => config?.settings.filter((s) => s.group === g) ?? [];
  const maintenanceOn = config?.settings.some(
    (s) => s.key === "maintenance.enabled" && s.value === true,
  );
  const settingList = (items: Setting[]) => (
    <ul className="divide-y divide-slate-200 dark:divide-navy-800">
      {items.map((s) => (
        <li key={s.key} className="py-4 first:pt-0 last:pb-0">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs">{s.key}</span>
            {s.overridden ? (
              <StatusBadge tone="info">{t("overridden")}</StatusBadge>
            ) : (
              <StatusBadge tone="neutral">{t("default")}</StatusBadge>
            )}
            {s.updated_at ? (
              <span className="gh-muted text-xs">
                {t("changedBy", { who: s.updated_by ?? "-", when: when(s.updated_at) })}
              </span>
            ) : null}
          </div>
          <ConfigSetting setting={s} label={label(s.key)} />
        </li>
      ))}
    </ul>
  );

  return (
    <>
      <PageHeader eyebrow={tConsole("eyebrow")} title={t("title")} intro={t("intro")} />

      <SafetyStatus
        active={settled(orchR)?.active ?? null}
        modules={settled(modulesR)}
        stats={settled(statsR)}
      />

      <Panel
        id="fixed-h"
        title={t("fixedTitle")}
        intro={t("fixedIntro")}
        emphasis="locked"
        actions={<StatusBadge tone="locked">{t("notEditable")}</StatusBadge>}
      >
        <ul className="space-y-2 text-sm">
          {FIXED.map((k) => (
            <li key={k} className="flex gap-2">
              <span aria-hidden="true">•</span>
              <span>{t(`fixed.${k}`)}</span>
            </li>
          ))}
        </ul>
        <p className="mt-3 text-sm">
          <Link href="/admin/scans" className="gh-link">
            {t("toLocks")}
          </Link>
        </p>
      </Panel>

      {!config ? (
        <p className="gh-muted text-sm">{tAdmin("unavailable")}</p>
      ) : (
        <>
          <Panel
            id="maintenance-h"
            title={t("maintenanceTitle")}
            intro={t("maintenanceIntro")}
            emphasis={maintenanceOn ? "warn" : undefined}
            actions={
              maintenanceOn ? (
                <StatusBadge tone="warn" size="lg">
                  {t("maintenanceOn")}
                </StatusBadge>
              ) : (
                <StatusBadge tone="ok">{t("maintenanceOff")}</StatusBadge>
              )
            }
          >
            {settingList(group("maintenance"))}
          </Panel>

          <div className="grid gap-6 lg:grid-cols-2">
            <Panel id="flags-h" title={t("flagsTitle")} intro={t("flagsIntro")}>
              {settingList(group("flags"))}
            </Panel>
            <Panel id="scans-h" title={t("scansTitle")} intro={t("scansIntro")}>
              {settingList([...group("scans"), ...group("concurrency")])}
            </Panel>
          </div>

          <Panel id="rates-h" title={t("ratesTitle")} intro={t("ratesIntro")}>
            {settingList(group("rate_limits"))}
          </Panel>

          <p className="gh-muted text-xs">{t("propagation", { seconds: config.cache_seconds })}</p>

          <Panel
            id="env-h"
            title={t("envTitle")}
            intro={t("envIntro")}
            bodyClassName="overflow-x-auto"
          >
            <table className="gh-table-admin">
              <caption className="sr-only">{t("envTitle")}</caption>
              <thead>
                <tr>
                  <th scope="col">{t("envName")}</th>
                  <th scope="col">{t("envValue")}</th>
                </tr>
              </thead>
              <tbody>
                {config.environment.map((e) => (
                  <tr key={e.name}>
                    <th scope="row" className="font-mono text-xs font-normal">
                      {e.name}
                    </th>
                    <td className="text-xs">
                      {e.kind === "value" ? (
                        <span className="font-mono">{e.value || t("empty")}</span>
                      ) : (
                        <StatusBadge tone={e.kind === "secret" ? "locked" : "neutral"}>
                          {e.configured
                            ? e.kind === "secret"
                              ? t("secretSet")
                              : t("hiddenSet")
                            : t("notSet")}
                        </StatusBadge>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Panel>

          <Panel
            id="history-h"
            title={t("historyTitle")}
            intro={t("historyIntro")}
            bodyClassName="overflow-x-auto"
          >
            {config.history.length === 0 ? (
              <p className="gh-muted px-5 py-4 text-sm">{t("noHistory")}</p>
            ) : (
              <table className="gh-table-admin">
                <caption className="sr-only">{t("historyTitle")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t("colWhen")}</th>
                    <th scope="col">{t("colWho")}</th>
                    <th scope="col">{t("colSetting")}</th>
                    <th scope="col">{t("colChange")}</th>
                    <th scope="col">{t("colReason")}</th>
                    <th scope="col">
                      <span className="sr-only">{t("revert")}</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {config.history.map((c) => (
                    <tr key={c.id}>
                      <td className="text-xs whitespace-nowrap">{when(c.at)}</td>
                      <td className="text-xs">
                        {c.actor_email ?? <HashId value={c.actor} chars={14} />}
                      </td>
                      <td className="text-xs">
                        <span className="block">{label(c.key)}</span>
                        <span className="gh-muted font-mono">{c.key}</span>
                      </td>
                      <td className="text-xs">
                        <span className="block">{t(`action.${c.action.split(".")[1]}`)}</span>
                        {shown(c.old)} → {shown(c.new)}
                      </td>
                      <td className="text-xs">{c.reason || "-"}</td>
                      <td>{c.revertible ? <ConfigRevert changeId={c.id} /> : null}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>
        </>
      )}
    </>
  );
}
