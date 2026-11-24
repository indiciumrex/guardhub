/**
 * Audit & monitoring (§8.3, §9.1): the append-only audit log (actor, time, keyed IP hash,
 * action, target, before/after) with filters, next to system health (components, module error
 * rates, queue, scanners) and recent errors (GuardHub's own records, plus Sentry when a read-only
 * token is configured).
 */
import type { Metadata } from "next";
import Link from "next/link";
import { getFormatter, getTranslations } from "next-intl/server";
import { ErrorList } from "@/components/admin/ErrorList";
import { Badge, Section, pct } from "@/components/admin/Stat";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import type { AuditDetail, Monitoring } from "@/lib/admin-types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("adminCenter.nav");
  return { title: t("audit") };
}

const SAFE = /^[\w.:@-]{1,128}$/;

export default async function AdminAuditPage({
  searchParams,
}: {
  searchParams: Promise<{ action?: string; actor?: string; target?: string; page?: string }>;
}) {
  const sp = await searchParams;
  const pick = (v?: string) => (v && SAFE.test(v) ? v : undefined);
  const action = pick(sp.action);
  const actor = pick(sp.actor);
  const target = pick(sp.target);
  const page = Math.max(0, Number.parseInt(sp.page ?? "0", 10) || 0);
  const [rows, mon] = await loadProtected(() =>
    Promise.all([
      serverApiFetch<AuditDetail[]>("/admin/audit", {
        query: { action, actor, target, limit: 100, offset: page * 100 },
      }),
      serverApiFetch<Monitoring>("/admin/monitoring").catch(() => null),
    ]),
  );
  const t = await getTranslations("adminCenter.audit");
  const tc = await getTranslations("adminCenter.common");
  const tHealth = await getTranslations("health");
  const format = await getFormatter();
  const when = (v: string | null) =>
    v
      ? format.dateTime(new Date(v), { dateStyle: "short", timeStyle: "medium", timeZone: "UTC" })
      : "-";
  const healthLabel = (s: string) => (tHealth.has(s) ? tHealth(s) : s);
  const query = (extra: Record<string, string>) =>
    `/admin/audit?${new URLSearchParams({
      ...(action ? { action } : {}),
      ...(actor ? { actor } : {}),
      ...(target ? { target } : {}),
      ...extra,
    })}`;

  return (
    <div className="space-y-10">
      <div>
        <h1 className="text-3xl font-bold">{t("title")}</h1>
        <p className="gh-muted mt-2 max-w-3xl">{t("intro")}</p>
      </div>

      {mon ? (
        <Section id="mon-h" title={t("monitoringHeading")}>
          <div className="grid gap-4 lg:grid-cols-3">
            <div className="gh-card p-5 text-sm">
              <h3 className="font-semibold">{t("system")}</h3>
              <dl className="mt-2 space-y-1">
                <div className="flex justify-between gap-3">
                  <dt>{t("overall")}</dt>
                  <dd>{healthLabel(mon.health.status)}</dd>
                </div>
                {Object.entries(mon.health.components).map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-3">
                    <dt>{tc.has(`component.${k}`) ? tc(`component.${k}`) : k}</dt>
                    <dd>{healthLabel(v)}</dd>
                  </div>
                ))}
                <div className="flex justify-between gap-3">
                  <dt>{tc("queue.lag")}</dt>
                  <dd className="tabular-nums">{mon.queue.lag ?? "-"}</dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt>{tc("queue.pending")}</dt>
                  <dd className="tabular-nums">{mon.queue.pending ?? "-"}</dd>
                </div>
              </dl>
              <h3 className="mt-4 font-semibold">{t("scanners")}</h3>
              <ul className="mt-1 space-y-1 text-xs">
                {mon.scanners.length === 0 ? (
                  <li className="gh-muted">{t("noScanners")}</li>
                ) : (
                  mon.scanners.map((s) => (
                    <li key={s.consumer}>
                      <span className="font-mono">{s.consumer}</span> ·{" "}
                      {s.version ? s.version.slice(0, 12) : "-"} ·{" "}
                      {t("scannerLimits", {
                        rps: s.host_rps,
                        budget: s.max_requests_per_scan,
                        workers: s.workers,
                      })}{" "}
                      ·{" "}
                      {s.active_enabled ? (
                        <Badge tone="warn">{t("activeOn")}</Badge>
                      ) : (
                        <Badge tone="good">{t("activeOff")}</Badge>
                      )}
                    </li>
                  ))
                )}
              </ul>
            </div>
            <div className="gh-card overflow-x-auto p-5 text-sm">
              <h3 className="font-semibold">{t("moduleHealth")}</h3>
              <table className="gh-table mt-2">
                <caption className="sr-only">{t("moduleHealth")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{tc("module")}</th>
                    <th scope="col">{t("status")}</th>
                    <th scope="col">{t("errorRate")}</th>
                  </tr>
                </thead>
                <tbody>
                  {mon.components.map((c) => (
                    <tr key={c.module_key}>
                      <th scope="row" className="font-mono text-xs font-normal">
                        {c.module_key}
                      </th>
                      <td>{healthLabel(c.status)}</td>
                      <td className="tabular-nums">{pct(c.error_rate)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="space-y-2">
              <h3 className="font-semibold">{t("errors")}</h3>
              <ErrorList
                items={[...mon.sentry.issues, ...mon.recent_errors].slice(0, 20)}
                when={when}
                none={tc("none")}
              />
              <p className="gh-muted text-xs">
                {mon.sentry.configured
                  ? mon.sentry.error
                    ? t("sentryUnavailable")
                    : t("sentryOn")
                  : t("sentryOff")}
              </p>
            </div>
          </div>
        </Section>
      ) : null}

      <Section id="audit-h" title={t("logHeading")} intro={t("logIntro")}>
        <form method="get" className="gh-card flex flex-wrap items-end gap-3 p-4 text-sm">
          <div>
            <label htmlFor="a-action" className="gh-label">
              {t("actionFilter")}
            </label>
            <input
              id="a-action"
              name="action"
              defaultValue={action ?? ""}
              placeholder="module."
              className="gh-input font-mono"
            />
          </div>
          <div>
            <label htmlFor="a-actor" className="gh-label">
              {t("actorFilter")}
            </label>
            <input
              id="a-actor"
              name="actor"
              defaultValue={actor ?? ""}
              className="gh-input font-mono"
            />
          </div>
          <div>
            <label htmlFor="a-target" className="gh-label">
              {t("targetFilter")}
            </label>
            <input
              id="a-target"
              name="target"
              defaultValue={target ?? ""}
              className="gh-input font-mono"
            />
          </div>
          <button type="submit" className="gh-btn gh-btn-secondary">
            {t("apply")}
          </button>
          <Link href="/admin/audit" className="gh-link">
            {t("clear")}
          </Link>
        </form>
        <div className="gh-card overflow-x-auto">
          <table className="gh-table">
            <caption className="sr-only">{t("logHeading")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("colTime")}</th>
                <th scope="col">{t("colActor")}</th>
                <th scope="col">{t("colAction")}</th>
                <th scope="col">{t("colTarget")}</th>
                <th scope="col">{t("colChanges")}</th>
                <th scope="col">{t("colIp")}</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={6} className="gh-muted">
                    {tc("none")}
                  </td>
                </tr>
              ) : (
                rows.map((r) => (
                  <tr key={r.id}>
                    <td className="whitespace-nowrap text-xs">{when(r.at)}</td>
                    <td className="break-all text-xs">
                      {r.actor_email ?? r.actor}
                      {r.actor_email ? (
                        <span className="gh-muted block font-mono">{r.actor}</span>
                      ) : null}
                    </td>
                    <td className="font-mono text-xs">{r.action}</td>
                    <td className="break-all font-mono text-xs">{r.target || "-"}</td>
                    <td className="text-xs">
                      {Object.keys(r.changes).length === 0 ? (
                        "-"
                      ) : (
                        <dl>
                          {Object.entries(r.changes).map(([k, v]) => (
                            <div key={k}>
                              <dt className="gh-muted inline">{k}: </dt>
                              <dd className="inline break-all font-mono">{v}</dd>
                            </div>
                          ))}
                        </dl>
                      )}
                    </td>
                    <td className="font-mono text-xs">{r.ip_hash ?? "-"}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        <p className="gh-muted text-xs">{t("ipNote")}</p>
        <nav aria-label={t("pagination")} className="flex gap-4 text-sm">
          {page > 0 ? (
            <Link className="gh-link" href={query({ page: String(page - 1) })}>
              {tc("previous")}
            </Link>
          ) : null}
          {rows.length === 100 ? (
            <Link className="gh-link" href={query({ page: String(page + 1) })}>
              {tc("next")}
            </Link>
          ) : null}
        </nav>
      </Section>
    </div>
  );
}
