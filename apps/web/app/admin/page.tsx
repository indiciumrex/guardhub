/**
 * Admin overview (§8.3): scans, findings by severity, module success rates, system health
 * (API, database, Redis, scanner, queue), recent admin actions and recent errors.
 * Each block loads independently, so one failing endpoint doesn't hide the others.
 */
import type { Metadata } from "next";
import Link from "next/link";
import { getFormatter, getTranslations } from "next-intl/server";
import { ErrorList } from "@/components/admin/ErrorList";
import { Badge, Section, Stat, pct } from "@/components/admin/Stat";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import type { AiStatus } from "@/lib/types";
import type { Overview } from "@/lib/admin-types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("admin");
  return { title: t("title") };
}

function settled<T>(result: PromiseSettledResult<T>): T | null {
  return result.status === "fulfilled" ? result.value : null;
}

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

export default async function AdminOverviewPage() {
  const [overviewR, aiR] = await loadProtected(() =>
    Promise.allSettled([
      serverApiFetch<Overview>("/admin/overview"),
      serverApiFetch<AiStatus>("/admin/ai"),
    ]),
  );
  const ov = settled(overviewR);
  const ai = settled(aiR);
  const t = await getTranslations("adminCenter.overview");
  const tc = await getTranslations("adminCenter.common");
  const tAdmin = await getTranslations("admin");
  const tHealth = await getTranslations("health");
  const tSev = await getTranslations("severity");
  const format = await getFormatter();
  const when = (v: string | null) =>
    v
      ? format.dateTime(new Date(v), { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" })
      : "-";
  const healthLabel = (s: string) => (tHealth.has(s) ? tHealth(s) : s);
  const unavailable = <p className="gh-muted text-sm">{tAdmin("unavailable")}</p>;

  return (
    <div className="space-y-10">
      <div>
        <h1 className="text-3xl font-bold">{tAdmin("title")}</h1>
        <p className="gh-muted mt-2 max-w-3xl">{t("intro")}</p>
      </div>

      {!ov ? (
        unavailable
      ) : (
        <>
          <Section id="scans-h" title={t("scansHeading")}>
            <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-8">
              <Stat label={t("total")} value={ov.scans.total} />
              <Stat label={t("last24h")} value={ov.scans.last_24h} />
              <Stat label={tc("lifecycle.queued")} value={ov.scans.queued} />
              <Stat label={tc("lifecycle.running")} value={ov.scans.running} />
              <Stat label={tc("lifecycle.completed")} value={ov.scans.completed} />
              <Stat label={tc("lifecycle.failed")} value={ov.scans.failed} />
              <Stat label={tc("lifecycle.timed_out")} value={ov.scans.timed_out} />
              <Stat label={tc("lifecycle.cancelled")} value={ov.scans.cancelled} />
            </dl>
            <Link href="/admin/scans" className="gh-link text-sm">
              {t("toScans")}
            </Link>
          </Section>

          <Section id="findings-h" title={t("findingsHeading")} intro={t("findingsIntro")}>
            <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
              <Stat label={t("total")} value={ov.findings.total} />
              {SEVERITIES.map((s) => (
                <Stat key={s} label={tSev(s)} value={ov.findings[s]} />
              ))}
            </dl>
            <Link href="/admin/findings" className="gh-link text-sm">
              {t("toFindings")}
            </Link>
          </Section>

          <Section id="health-h" title={t("healthHeading")}>
            <div className="grid gap-4 md:grid-cols-3">
              <div className="gh-card p-5">
                <h3 className="font-semibold">{t("components")}</h3>
                <dl className="mt-3 space-y-1 text-sm">
                  <div className="flex justify-between gap-3">
                    <dt className="font-semibold">{tAdmin("overall")}</dt>
                    <dd>{healthLabel(ov.health.status)}</dd>
                  </div>
                  {Object.entries(ov.health.components).map(([name, status]) => (
                    <div key={name} className="flex justify-between gap-3">
                      <dt>{tc.has(`component.${name}`) ? tc(`component.${name}`) : name}</dt>
                      <dd>{healthLabel(status)}</dd>
                    </div>
                  ))}
                </dl>
              </div>
              <div className="gh-card p-5">
                <h3 className="font-semibold">{t("queue")}</h3>
                {ov.queue.available ? (
                  <dl className="mt-3 space-y-1 text-sm">
                    <div className="flex justify-between gap-3">
                      <dt>{tc("queue.lag")}</dt>
                      <dd className="tabular-nums">{ov.queue.lag ?? "-"}</dd>
                    </div>
                    <div className="flex justify-between gap-3">
                      <dt>{tc("queue.pending")}</dt>
                      <dd className="tabular-nums">{ov.queue.pending ?? "-"}</dd>
                    </div>
                    <div className="flex justify-between gap-3">
                      <dt>{tc("queue.consumers")}</dt>
                      <dd className="tabular-nums">{ov.queue.consumers ?? "-"}</dd>
                    </div>
                  </dl>
                ) : (
                  unavailable
                )}
              </div>
              <div className="gh-card p-5">
                <h3 className="font-semibold">{tAdmin("aiHeading")}</h3>
                {ai ? (
                  <p className="mt-3 text-sm">
                    {ai.active
                      ? tAdmin("aiActive", { provider: ai.provider ?? "-" })
                      : tAdmin("aiNotConfigured")}
                  </p>
                ) : (
                  unavailable
                )}
              </div>
            </div>
          </Section>

          <Section id="rates-h" title={t("ratesHeading")} intro={t("ratesIntro")}>
            {ov.modules.length === 0 ? (
              <p className="gh-muted text-sm">{t("noRuns")}</p>
            ) : (
              <div className="gh-card overflow-x-auto">
                <table className="gh-table">
                  <caption className="sr-only">{t("ratesHeading")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{tc("module")}</th>
                      <th scope="col">{t("runs")}</th>
                      <th scope="col">{t("couldNotRun")}</th>
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
                        <td>
                          <Badge
                            tone={
                              m.success_rate === null
                                ? "neutral"
                                : m.success_rate >= 0.95
                                  ? "good"
                                  : m.success_rate >= 0.8
                                    ? "warn"
                                    : "bad"
                            }
                          >
                            {pct(m.success_rate)}
                          </Badge>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Section>

          <div className="grid gap-6 lg:grid-cols-2">
            <Section id="audit-h" title={t("auditHeading")}>
              <ul className="gh-card divide-y divide-slate-200 text-sm dark:divide-navy-700">
                {ov.recent_audit.length === 0 ? (
                  <li className="gh-muted p-3">{tc("none")}</li>
                ) : (
                  ov.recent_audit.map((a) => (
                    <li key={a.id} className="p-3">
                      <span className="font-mono text-xs">{a.action}</span>{" "}
                      <span className="gh-muted">
                        {a.actor_email ?? a.actor} · {when(a.at)}
                      </span>
                    </li>
                  ))
                )}
              </ul>
              <Link href="/admin/audit" className="gh-link text-sm">
                {t("toAudit")}
              </Link>
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
    </div>
  );
}
