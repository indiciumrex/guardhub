/**
 * API & integrations (Admin Panel, Prompt 2 §4): what a key can never do comes first, then the
 * keys (create, scopes, expiry, revoke) and the endpoint traffic (requests, errors, latency,
 * rate limiting) per route template.
 */
import type { Metadata } from "next";
import Link from "next/link";
import { getFormatter, getTranslations } from "next-intl/server";
import { CreateApiKey, RevokeApiKey } from "@/components/admin/ApiKeyControls";
import { PageHeader, Panel, StatusBadge, type Tone } from "@/components/admin/Stat";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import type { ApiKeyView, EndpointTraffic } from "@/lib/admin-types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("adminCenter.integrations");
  return { title: t("title") };
}

const HOURS = [1, 24, 48] as const;
const STATUS_TONE: Record<ApiKeyView["status"], Tone> = {
  active: "ok",
  expired: "neutral",
  revoked: "locked",
};

export default async function AdminIntegrationsPage({
  searchParams,
}: {
  searchParams: Promise<{ hours?: string }>;
}) {
  const sp = await searchParams;
  const hours = (HOURS as readonly number[]).includes(Number(sp.hours)) ? Number(sp.hours) : 24;
  const [keysR, trafficR] = await loadProtected(() =>
    Promise.allSettled([
      serverApiFetch<ApiKeyView[]>("/admin/integrations/keys"),
      serverApiFetch<EndpointTraffic[]>("/admin/integrations/traffic", { query: { hours } }),
    ]),
  );
  const keys = keysR.status === "fulfilled" ? keysR.value : null;
  const trafficRows = trafficR.status === "fulfilled" ? trafficR.value : null;
  const t = await getTranslations("adminCenter.integrations");
  const tConsole = await getTranslations("adminCenter.console");
  const tAdmin = await getTranslations("admin");
  const format = await getFormatter();
  const when = (v: string | null) =>
    v
      ? format.dateTime(new Date(v), { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" })
      : "-";
  const pct = (v: number) => `${(v * 100).toFixed(v === 0 ? 0 : 1)}%`;

  return (
    <>
      <PageHeader eyebrow={tConsole("eyebrow")} title={t("title")} intro={t("intro")} />

      <Panel
        id="boundary-h"
        title={t("boundaryTitle")}
        emphasis="locked"
        actions={<StatusBadge tone="locked">{t("enforced")}</StatusBadge>}
      >
        <ul className="space-y-2 text-sm">
          {(["noAdmin", "userRole", "proof", "hashed", "limits"] as const).map((k) => (
            <li key={k} className="flex gap-2">
              <span aria-hidden="true">•</span>
              <span>{t(`boundary.${k}`)}</span>
            </li>
          ))}
        </ul>
        <p className="gh-muted mt-3 text-xs">{t("howTo")}</p>
        <pre className="mt-2 overflow-x-auto rounded bg-slate-100 p-3 text-xs dark:bg-navy-950">
          {`curl -H "Authorization: Bearer ghk_…" https://guardhub.dev/api/v1/integrations/projects
curl -X POST -H "Authorization: Bearer ghk_…" -H "X-GuardHub-CSRF: 1" \\
  https://guardhub.dev/api/v1/integrations/projects/<id>/scans`}
        </pre>
      </Panel>

      <Panel id="keys-h" title={t("keysTitle")} intro={t("keysIntro")}>
        <CreateApiKey />
        {!keys ? (
          <p className="gh-muted mt-4 text-sm">{tAdmin("unavailable")}</p>
        ) : keys.length === 0 ? (
          <p className="gh-muted mt-4 text-sm">{t("noKeys")}</p>
        ) : (
          <div className="mt-4 overflow-x-auto">
            <table className="gh-table-admin">
              <caption className="sr-only">{t("keysTitle")}</caption>
              <thead>
                <tr>
                  <th scope="col">{t("colName")}</th>
                  <th scope="col">{t("colKey")}</th>
                  <th scope="col">{t("colScopes")}</th>
                  <th scope="col">{t("colStatus")}</th>
                  <th scope="col">{t("colExpires")}</th>
                  <th scope="col">{t("colLastUsed")}</th>
                  <th scope="col">
                    <span className="sr-only">{t("revoke")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {keys.map((k) => (
                  <tr key={k.id}>
                    <th scope="row" className="text-sm font-medium">
                      {k.name}
                      <span className="gh-muted block text-xs font-normal">
                        {k.owner_email ?? "-"}
                      </span>
                    </th>
                    <td className="font-mono text-xs">{k.prefix}…</td>
                    <td className="text-xs">
                      {k.scopes.map((s) => t(`scope.${s.replace(":", "_")}`)).join(", ")}
                    </td>
                    <td>
                      <StatusBadge tone={STATUS_TONE[k.status]}>
                        {t(`status.${k.status}`)}
                      </StatusBadge>
                    </td>
                    <td className="text-xs whitespace-nowrap">{when(k.expires_at)}</td>
                    <td className="text-xs whitespace-nowrap">{when(k.last_used_at)}</td>
                    <td>
                      {k.status === "active" ? <RevokeApiKey keyId={k.id} name={k.name} /> : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Panel
        id="traffic-h"
        title={t("trafficTitle")}
        intro={t("trafficIntro")}
        bodyClassName="overflow-x-auto"
        actions={
          <ul aria-label={t("hoursLabel")} className="flex gap-2">
            {HOURS.map((h) => (
              <li key={h}>
                <Link
                  href={`/admin/integrations?hours=${h}`}
                  aria-current={h === hours ? "page" : undefined}
                  className={`inline-flex min-h-9 items-center rounded-full border px-3 text-xs font-semibold ${
                    h === hours
                      ? "border-navy-900 bg-navy-900 text-white dark:border-teal-300 dark:bg-teal-300 dark:text-navy-950"
                      : "border-slate-300 dark:border-navy-700"
                  }`}
                >
                  {t("hours", { hours: h })}
                </Link>
              </li>
            ))}
          </ul>
        }
      >
        {!trafficRows ? (
          <p className="gh-muted px-5 py-4 text-sm">{tAdmin("unavailable")}</p>
        ) : trafficRows.length === 0 ? (
          <p className="gh-muted px-5 py-4 text-sm">{t("noTraffic")}</p>
        ) : (
          <table className="gh-table-admin">
            <caption className="sr-only">{t("trafficTitle")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("colEndpoint")}</th>
                <th scope="col">{t("colRequests")}</th>
                <th scope="col">{t("col4xx")}</th>
                <th scope="col">{t("col5xx")}</th>
                <th scope="col">{t("col429")}</th>
                <th scope="col">{t("colAvg")}</th>
                <th scope="col">{t("colP95")}</th>
              </tr>
            </thead>
            <tbody>
              {trafficRows.map((r) => (
                <tr key={r.endpoint}>
                  <th scope="row" className="font-mono text-xs font-normal">
                    {r.endpoint}
                  </th>
                  <td className="text-xs tabular-nums">{r.requests}</td>
                  <td className="text-xs tabular-nums">{r.client_errors}</td>
                  <td className="text-xs">
                    {r.server_errors ? (
                      <StatusBadge tone="crit">
                        {r.server_errors} ({pct(r.error_rate)})
                      </StatusBadge>
                    ) : (
                      "0"
                    )}
                  </td>
                  <td className="text-xs tabular-nums">{r.rate_limited}</td>
                  <td className="text-xs tabular-nums">{r.avg_ms} ms</td>
                  <td className="text-xs tabular-nums">
                    {r.p95_ms === null ? t("over5s") : `≤ ${r.p95_ms} ms`}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </>
  );
}
