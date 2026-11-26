/**
 * Admin overview (§8.3): the first-use guide (add a site → verify → scan) until it is done, then
 * the safety status (active-testing locks, lab gates, false-positive
 * rate), then scans, findings by severity, system health (API, database, Redis, scanner, queue),
 * module success rates, recent admin actions and recent errors.
 * Each block loads independently, so one failing endpoint doesn't hide the others.
 */
import type { Metadata } from "next";
import Link from "next/link";
import { getFormatter, getTranslations } from "next-intl/server";
import { ErrorList } from "@/components/admin/ErrorList";
import { SafetyStatus } from "@/components/admin/SafetyStatus";
import { StartGuide } from "@/components/admin/StartGuide";
import {
  KV,
  PageHeader,
  Panel,
  Section,
  Stat,
  StatusBadge,
  pct,
  type Tone,
} from "@/components/admin/Stat";
import { SeverityIcon } from "@/components/scan/SeverityBadge";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import type { AiStatus } from "@/lib/types";
import type { CenterModule, ModuleStats, Orchestration, Overview } from "@/lib/admin-types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("admin");
  return { title: t("title") };
}

function settled<T>(result: PromiseSettledResult<T>): T | null {
  return result.status === "fulfilled" ? result.value : null;
}

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

function healthTone(status: string): Tone {
  if (status === "ok" || status === "healthy") return "ok";
  if (status === "degraded") return "warn";
  if (status === "down" || status === "error" || status === "unhealthy") return "crit";
  return "neutral";
}

export default async function AdminOverviewPage() {
  const [overviewR, aiR, orchR, modulesR, statsR] = await loadProtected(() =>
    Promise.allSettled([
      serverApiFetch<Overview>("/admin/overview"),
      serverApiFetch<AiStatus>("/admin/ai"),
      serverApiFetch<Orchestration>("/admin/orchestration"),
      serverApiFetch<CenterModule[]>("/admin/modules"),
      serverApiFetch<ModuleStats[]>("/admin/modules/stats"),
    ]),
  );
  const ov = settled(overviewR);
  const ai = settled(aiR);
  const t = await getTranslations("adminCenter.overview");
  const tc = await getTranslations("adminCenter.common");
  const tAdmin = await getTranslations("admin");
  const tHealth = await getTranslations("health");
  const tSev = await getTranslations("severity");
  const tConsole = await getTranslations("adminCenter.console");
  const format = await getFormatter();
  const when = (v: string | null) =>
    v
      ? format.dateTime(new Date(v), { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" })
      : "-";
  const healthLabel = (s: string) => (tHealth.has(s) ? tHealth(s) : s);
  const unavailable = <p className="gh-muted text-sm">{tAdmin("unavailable")}</p>;

  return (
    <>
      <PageHeader eyebrow={tConsole("eyebrow")} title={tAdmin("title")} intro={t("intro")} />

      <StartGuide />

      <SafetyStatus
        active={settled(orchR)?.active ?? null}
        modules={settled(modulesR)}
        stats={settled(statsR)}
      />

      {!ov ? (
        unavailable
      ) : (
        <>
          <Section
            id="scans-h"
            title={t("scansHeading")}
            actions={
              <Link href="/admin/scans" className="gh-link text-sm">
                {t("toScans")}
              </Link>
            }
          >
            <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-8">
              <Stat label={t("total")} value={ov.scans.total} />
              <Stat label={t("last24h")} value={ov.scans.last_24h} />
              <Stat label={tc("lifecycle.queued")} value={ov.scans.queued} />
              <Stat label={tc("lifecycle.running")} value={ov.scans.running} />
              <Stat label={tc("lifecycle.completed")} value={ov.scans.completed} tone="ok" />
              <Stat
                label={tc("lifecycle.failed")}
                value={ov.scans.failed}
                tone={ov.scans.failed ? "crit" : undefined}
              />
              <Stat
                label={tc("lifecycle.timed_out")}
                value={ov.scans.timed_out}
                tone={ov.scans.timed_out ? "warn" : undefined}
              />
              <Stat label={tc("lifecycle.cancelled")} value={ov.scans.cancelled} />
            </dl>
          </Section>

          <Section
            id="findings-h"
            title={t("findingsHeading")}
            intro={t("findingsIntro")}
            actions={
              <Link href="/admin/findings" className="gh-link text-sm">
                {t("toFindings")}
              </Link>
            }
          >
            <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
              <Stat label={t("total")} value={ov.findings.total} />
              {SEVERITIES.map((s) => (
                <div key={s} className="gh-panel px-4 py-3">
                  <dt className="gh-eyebrow flex items-center gap-1.5">
                    <SeverityIcon severity={s} className="h-3.5 w-3.5" />
                    {tSev(s)}
                  </dt>
                  <dd className="mt-1 text-2xl font-semibold tabular-nums">{ov.findings[s]}</dd>
                </div>
              ))}
            </dl>
          </Section>

          <Section id="health-h" title={t("healthHeading")}>
            <div className="grid gap-4 md:grid-cols-3">
              <Panel
                id="components-h"
                title={t("components")}
                actions={
                  <StatusBadge tone={healthTone(ov.health.status)}>
                    {healthLabel(ov.health.status)}
                  </StatusBadge>
                }
              >
                <KV
                  rows={Object.entries(ov.health.components).map(([name, status]) => ({
                    key: name,
                    label: tc.has(`component.${name}`) ? tc(`component.${name}`) : name,
                    value: (
                      <StatusBadge tone={healthTone(status)}>{healthLabel(status)}</StatusBadge>
                    ),
                  }))}
                />
              </Panel>
              <Panel id="queue-h" title={t("queue")}>
                {ov.queue.available ? (
                  <KV
                    rows={[
                      { label: tc("queue.lag"), value: ov.queue.lag ?? "-" },
                      { label: tc("queue.pending"), value: ov.queue.pending ?? "-" },
                      { label: tc("queue.consumers"), value: ov.queue.consumers ?? "-" },
                    ]}
                  />
                ) : (
                  unavailable
                )}
              </Panel>
              <Panel id="ai-h" title={tAdmin("aiHeading")}>
                {ai ? (
                  <p className="text-sm">
                    {ai.active
                      ? tAdmin("aiActive", { provider: ai.provider ?? "-" })
                      : tAdmin("aiNotConfigured")}
                  </p>
                ) : (
                  unavailable
                )}
              </Panel>
            </div>
          </Section>

          <Section id="rates-h" title={t("ratesHeading")} intro={t("ratesIntro")}>
            {ov.modules.length === 0 ? (
              <p className="gh-muted text-sm">{t("noRuns")}</p>
            ) : (
              <div className="gh-panel overflow-x-auto">
                <table className="gh-table-admin">
                  <caption className="sr-only">{t("ratesHeading")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{tc("module")}</th>
                      <th scope="col">{t("runs")}</th>
                      <th scope="col">{t("couldNotRun")}</th>
                      <th scope="col">{t("safeStopped")}</th>
                      <th scope="col">{t("successRate")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ov.modules.map((m) => (
                      <tr key={m.check_id}>
                        <th scope="row" className="font-mono text-xs font-normal">
                          {m.check_id}
                        </th>
                        <td className="tabular-nums">{m.runs}</td>
                        <td className="tabular-nums">{m.failed}</td>
                        <td className="tabular-nums">{m.safe_stopped}</td>
                        <td>
                          <StatusBadge
                            tone={
                              m.success_rate === null
                                ? "neutral"
                                : m.success_rate >= 0.95
                                  ? "ok"
                                  : m.success_rate >= 0.8
                                    ? "warn"
                                    : "crit"
                            }
                          >
                            {pct(m.success_rate)}
                          </StatusBadge>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Section>

          <div className="grid gap-6 lg:grid-cols-2">
            <Section
              id="audit-h"
              title={t("auditHeading")}
              actions={
                <Link href="/admin/audit" className="gh-link text-sm">
                  {t("toAudit")}
                </Link>
              }
            >
              <ul className="gh-panel divide-y divide-slate-200 text-sm dark:divide-navy-800">
                {ov.recent_audit.length === 0 ? (
                  <li className="gh-muted px-5 py-3">{tc("none")}</li>
                ) : (
                  ov.recent_audit.map((a) => (
                    <li key={a.id} className="flex flex-wrap items-baseline gap-x-3 px-5 py-2.5">
                      <span className="font-mono text-xs font-semibold">{a.action}</span>
                      <span className="gh-muted text-xs">
                        {a.actor_email ?? a.actor} · {when(a.at)}
                      </span>
                    </li>
                  ))
                )}
              </ul>
            </Section>
            <Section id="errors-h" title={t("errorsHeading")}>
              <ErrorList
                items={[...ov.sentry.issues, ...ov.recent_errors].slice(0, 10)}
                when={when}
                none={tc("none")}
              />
              <p className="gh-muted text-xs">
                {ov.sentry.configured
                  ? ov.sentry.error
                    ? t("sentryUnavailable")
                    : t("sentryOn")
                  : t("sentryOff")}
              </p>
            </Section>
          </div>
        </>
      )}
    </>
  );
}
