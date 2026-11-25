/**
 * Scan orchestration (§8.3): the scan lifecycle (queued, running, completed, failed, timed out,
 * cancelled) with cancel / run again, each scan's ownership proof (§9.2), the active-testing
 * state (Phase 4B: founder approval, scanner switch, kill switch, modules), the kill switch, the
 * rate limits the scanners run with, and the queue backlog (backpressure).
 */
import type { Metadata } from "next";
import Link from "next/link";
import { getFormatter, getTranslations } from "next-intl/server";
import { KillSwitch } from "@/components/admin/KillSwitch";
import { OwnerActiveScan } from "@/components/admin/OwnerActiveScan";
import { ScanActions } from "@/components/admin/ScanActions";
import { Badge, Section, Stat } from "@/components/admin/Stat";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import {
  LIFECYCLES,
  type AdminScan,
  type Lifecycle,
  type Orchestration,
  type OwnerScanReadiness,
} from "@/lib/admin-types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("adminCenter.nav");
  return { title: t("scans") };
}

const lifecycleTone: Record<Lifecycle, "good" | "warn" | "bad" | "neutral"> = {
  queued: "neutral",
  running: "neutral",
  completed: "good",
  failed: "bad",
  timed_out: "bad",
  cancelled: "warn",
};

export default async function ScanOrchestrationPage({
  searchParams,
}: {
  searchParams: Promise<{ stage?: string; page?: string }>;
}) {
  const sp = await searchParams;
  const stage = LIFECYCLES.includes(sp.stage as Lifecycle) ? (sp.stage as Lifecycle) : undefined;
  const page = Math.max(0, Number.parseInt(sp.page ?? "0", 10) || 0);
  const [orch, scans, owner] = await loadProtected(() =>
    Promise.all([
      serverApiFetch<Orchestration>("/admin/orchestration"),
      serverApiFetch<AdminScan[]>("/admin/scans/detailed", {
        query: { stage, limit: 50, offset: page * 50 },
      }),
      serverApiFetch<OwnerScanReadiness>("/admin/active/owner-scan"),
    ]),
  );
  const t = await getTranslations("adminCenter.scans");
  const tc = await getTranslations("adminCenter.common");
  const format = await getFormatter();
  const when = (v: string | null) =>
    v
      ? format.dateTime(new Date(v), { dateStyle: "short", timeStyle: "short", timeZone: "UTC" })
      : "-";
  const a = orch.active;
  const onOff = (v: boolean) => (v ? tc("on") : tc("off"));

  return (
    <div className="space-y-10">
      <div>
        <h1 className="text-3xl font-bold">{t("title")}</h1>
        <p className="gh-muted mt-2 max-w-3xl">{t("intro")}</p>
      </div>

      <Section id="active-h" title={t("activeHeading")} intro={t("activeIntro")}>
        <div className="grid gap-4 lg:grid-cols-2">
          <div className="gh-card p-5">
            <p className="text-lg font-semibold">
              {t("effective")}:{" "}
              <Badge tone={a.effective === "on" ? "warn" : "good"}>
                {a.effective === "on" ? tc("on") : tc("off")}
              </Badge>
            </p>
            <dl className="mt-3 space-y-1 text-sm">
              <div className="flex justify-between gap-3">
                <dt>{t("approved")}</dt>
                <dd>{onOff(a.approved)}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt>{t("scannerSwitch")}</dt>
                <dd>{a.scanner_switch === "unknown" ? tc("unknown") : tc(a.scanner_switch)}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt>{t("modulesOn")}</dt>
                <dd>{a.modules_on.length ? a.modules_on.join(", ") : tc("none")}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt>{t("oob")}</dt>
                <dd>{onOff(a.oob_configured)}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt>{t("globalKill")}</dt>
                <dd>{a.global_kill ? t("killEngaged") : t("killReleased")}</dd>
              </div>
            </dl>
            <p className="gh-muted mt-3 text-xs">{t("effectiveRule")}</p>
          </div>
          <div className="gh-card p-5">
            <h3 className="font-semibold">{t("killHeading")}</h3>
            <p className="gh-muted mb-3 mt-1 text-xs">{t("killIntro")}</p>
            <KillSwitch engaged={a.global_kill} />
          </div>
        </div>
        <div className="gh-card mt-4 p-5" id="owner-scan">
          <h3 className="font-semibold">{t("ownerHeading")}</h3>
          <p className="gh-muted mb-3 mt-1 text-xs">{t("ownerIntro")}</p>
          <OwnerActiveScan readiness={owner} />
        </div>
      </Section>

      <Section id="limits-h" title={t("limitsHeading")} intro={t("limitsIntro")}>
        <div className="grid gap-4 md:grid-cols-3">
          <div className="gh-card p-5 text-sm">
            <h3 className="font-semibold">{t("passiveLimits")}</h3>
            {orch.passive_limits ? (
              <dl className="mt-2 space-y-1">
                {Object.entries(orch.passive_limits).map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-3">
                    <dt>{tc.has(`limit.${k}`) ? tc(`limit.${k}`) : k}</dt>
                    <dd className="tabular-nums">{v}</dd>
                  </div>
                ))}
              </dl>
            ) : (
              <p className="gh-muted mt-2">{t("noScannerReport")}</p>
            )}
          </div>
          <div className="gh-card p-5 text-sm">
            <h3 className="font-semibold">{t("activeLimits")}</h3>
            <dl className="mt-2 space-y-1">
              {Object.entries(orch.active_limits).map(([k, v]) => (
                <div key={k} className="flex justify-between gap-3">
                  <dt>{tc.has(`limit.${k}`) ? tc(`limit.${k}`) : k}</dt>
                  <dd className="tabular-nums">{v}</dd>
                </div>
              ))}
            </dl>
          </div>
          <div className="gh-card p-5 text-sm">
            <h3 className="font-semibold">{t("backpressure")}</h3>
            {orch.queue.available ? (
              <dl className="mt-2 space-y-1">
                <div className="flex justify-between gap-3">
                  <dt>{tc("queue.lag")}</dt>
                  <dd className="tabular-nums">{orch.queue.lag ?? "-"}</dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt>{tc("queue.pending")}</dt>
                  <dd className="tabular-nums">{orch.queue.pending ?? "-"}</dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt>{tc("queue.consumers")}</dt>
                  <dd className="tabular-nums">{orch.queue.consumers ?? "-"}</dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt>{tc("queue.scanners")}</dt>
                  <dd className="tabular-nums">{orch.scanners.length}</dd>
                </div>
              </dl>
            ) : (
              <p className="gh-muted mt-2">{tc("unavailable")}</p>
            )}
          </div>
        </div>
      </Section>

      <Section id="lifecycle-h" title={t("lifecycleHeading")}>
        <dl className="grid grid-cols-3 gap-3 sm:grid-cols-6">
          {LIFECYCLES.map((l) => (
            <Stat
              key={l}
              label={tc(`lifecycle.${l}`)}
              value={orch.counts[l === "completed" ? "completed" : l]}
            />
          ))}
        </dl>
        <nav aria-label={t("filterLabel")} className="flex flex-wrap gap-2 text-sm">
          <Link href="/admin/scans" aria-current={!stage ? "page" : undefined} className="gh-link">
            {tc("all")}
          </Link>
          {LIFECYCLES.map((l) => (
            <Link
              key={l}
              href={`/admin/scans?stage=${l}`}
              aria-current={stage === l ? "page" : undefined}
              className={`gh-link ${stage === l ? "font-bold" : ""}`}
            >
              {tc(`lifecycle.${l}`)}
            </Link>
          ))}
        </nav>
        <div className="gh-card overflow-x-auto">
          <table className="gh-table">
            <caption className="sr-only">{t("lifecycleHeading")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("colTarget")}</th>
                <th scope="col">{t("colLifecycle")}</th>
                <th scope="col">{t("colProof")}</th>
                <th scope="col">{t("colTimes")}</th>
                <th scope="col">{t("colChecks")}</th>
                <th scope="col">{t("colActions")}</th>
              </tr>
            </thead>
            <tbody>
              {scans.length === 0 ? (
                <tr>
                  <td colSpan={6} className="gh-muted">
                    {tc("none")}
                  </td>
                </tr>
              ) : (
                scans.map((s) => (
                  <tr key={s.id}>
                    <td className="align-top">
                      <span className="break-all">{s.target_url}</span>
                      <span className="gh-muted block text-xs">
                        {s.project_name ?? t("anonymous")}
                        {s.owner_email ? ` · ${s.owner_email}` : ""} · {t(`trigger.${s.trigger}`)}
                      </span>
                      <Link href={`/admin/scans/${s.id}`} className="gh-link text-xs">
                        {t("details")}
                      </Link>
                    </td>
                    <td className="align-top">
                      <Badge tone={lifecycleTone[s.lifecycle]}>
                        {tc(`lifecycle.${s.lifecycle}`)}
                      </Badge>
                      {s.error && s.lifecycle === "failed" ? (
                        <span className="gh-muted block font-mono text-xs">{s.error}</span>
                      ) : null}
                      {s.score !== null ? (
                        <span className="gh-muted block text-xs">
                          {t("score", { score: s.score })}
                        </span>
                      ) : null}
                    </td>
                    <td className="align-top text-xs">
                      {s.ownership.kind === "none" ? (
                        <Badge tone="bad">{t("proof.none")}</Badge>
                      ) : (
                        <>
                          <Badge tone={s.ownership.verified_at ? "good" : "bad"}>
                            {t(`proof.${s.ownership.kind}`)}
                          </Badge>
                          <span className="gh-muted block">
                            {s.ownership.method ? t(`method.${s.ownership.method}`) : "-"} ·{" "}
                            {when(s.ownership.verified_at)}
                          </span>
                        </>
                      )}
                    </td>
                    <td className="whitespace-nowrap align-top text-xs">
                      {when(s.created_at)}
                      <span className="gh-muted block">
                        {s.duration_seconds !== null
                          ? t("duration", { seconds: s.duration_seconds })
                          : "-"}
                      </span>
                    </td>
                    <td className="align-top text-xs tabular-nums">
                      {s.checks}
                      {s.failed_checks.length ? (
                        <span className="block text-red-800 dark:text-red-200">
                          {t("checksFailed", { count: s.failed_checks.length })}
                        </span>
                      ) : null}
                    </td>
                    <td className="align-top">
                      <ScanActions scan={s} />
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        <nav aria-label={t("pagination")} className="flex gap-4 text-sm">
          {page > 0 ? (
            <Link
              className="gh-link"
              href={`/admin/scans?${new URLSearchParams({ ...(stage ? { stage } : {}), page: String(page - 1) })}`}
            >
              {tc("previous")}
            </Link>
          ) : null}
          {scans.length === 50 ? (
            <Link
              className="gh-link"
              href={`/admin/scans?${new URLSearchParams({ ...(stage ? { stage } : {}), page: String(page + 1) })}`}
            >
              {tc("next")}
            </Link>
          ) : null}
        </nav>
      </Section>
    </div>
  );
}
