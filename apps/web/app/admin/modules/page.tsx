/**
 * Module Center (§8.3): every module with its id, category, stage, status and the lab gate
 * behind it (Gate L for passive checks, Gate M for active ones: precision, recall, lab
 * false-positive rate, measured revision), the production triage (false positives marked by
 * admins), the last 7 days' success rate, config (maintenance, plan) and a changelog.
 *
 * The rule "no gate, no ON" is visible here: a module that may not be switched on shows a lock
 * and the reason instead of a switch. The API enforces the same rule; this page only shows it.
 */
import type { Metadata } from "next";
import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { ModuleConfig } from "@/components/admin/ModuleConfig";
import { ModuleToggle } from "@/components/admin/ModuleToggle";
import { HashId, PageHeader, Panel, Section, StatusBadge, pct } from "@/components/admin/Stat";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import type { AdminModule } from "@/lib/types";
import type { CenterModule, ModuleStats } from "@/lib/admin-types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("adminCenter.nav");
  return { title: t("modules") };
}

export default async function ModuleCenterPage() {
  const [modules, stats] = await loadProtected(() =>
    Promise.all([
      serverApiFetch<CenterModule[]>("/admin/modules"),
      serverApiFetch<ModuleStats[]>("/admin/modules/stats").catch(() => [] as ModuleStats[]),
    ]),
  );
  const t = await getTranslations("adminCenter.modules");
  const tc = await getTranslations("adminCenter.common");
  const byCheck = new Map(stats.map((s) => [s.check_id, s]));
  const statusTone = { active: "ok", maintenance: "warn", disabled: "neutral" } as const;
  const tConsole = await getTranslations("adminCenter.console");

  return (
    <>
      <PageHeader eyebrow={tConsole("eyebrow")} title={t("title")} intro={t("intro")} />

      <div role="note">
        <Panel emphasis="locked">
          <p className="flex items-center gap-2 font-semibold">
            <StatusBadge tone="locked">{t("ruleTitle")}</StatusBadge>
          </p>
          <p className="mt-2 max-w-3xl text-sm">{t("ruleBody")}</p>
        </Panel>
      </div>

      <Section id="modules-h" title={t("tableHeading")}>
        <div className="gh-panel overflow-x-auto">
          <table className="gh-table-admin min-w-[72rem]">
            <caption className="sr-only">{t("tableHeading")}</caption>
            <thead>
              <tr>
                <th scope="col">{tc("module")}</th>
                <th scope="col">{t("colStatus")}</th>
                <th scope="col">{t("colGate")}</th>
                <th scope="col">{t("colLab")}</th>
                <th scope="col">{t("colProduction")}</th>
                <th scope="col">{t("colSwitch")}</th>
                <th scope="col">{t("colConfig")}</th>
              </tr>
            </thead>
            <tbody>
              {modules.map((m) => {
                const s = byCheck.get(m.key);
                const g = m.gate;
                return (
                  <tr key={m.key}>
                    <th scope="row" className="align-top font-medium">
                      {m.name}
                      <span className="gh-muted block font-mono text-xs font-normal">{m.key}</span>
                      <span className="gh-muted block text-xs font-normal">
                        {t("category", { category: m.category })}
                      </span>
                      <Link
                        href={`/admin/audit?target=${encodeURIComponent(m.key)}&action=module.`}
                        className="gh-link text-xs font-normal"
                      >
                        {t("changelog")}
                      </Link>
                    </th>
                    <td className="space-y-1 align-top">
                      <StatusBadge tone={statusTone[m.status]}>
                        {t(`status.${m.status}`)}
                      </StatusBadge>
                      {m.stage === "beta" ? (
                        <span className="block">
                          <StatusBadge tone="info">{t("beta")}</StatusBadge>
                        </span>
                      ) : null}
                    </td>
                    <td className="align-top text-sm">
                      {!m.is_check ? (
                        <span className="gh-muted">{t("notACheck")}</span>
                      ) : g && g.measured ? (
                        <>
                          <StatusBadge tone={g.meets_gate ? "ok" : "crit"}>
                            {t(g.meets_gate ? "gateMet" : "gateNotMet", { gate: g.gate })}
                          </StatusBadge>
                          <span className="gh-muted mt-1 block text-xs">
                            {t("measuredAt", { source: "" })}
                            <HashId value={g.source} chars={7} />
                          </span>
                        </>
                      ) : (
                        <StatusBadge tone="crit">
                          {t("notMeasured", { gate: g?.gate ?? "L" })}
                        </StatusBadge>
                      )}
                    </td>
                    <td className="align-top text-xs tabular-nums">
                      {g && g.measured ? (
                        <dl className="space-y-0.5">
                          <div>
                            <dt className="inline">{t("precision")}: </dt>
                            <dd className="inline">{pct(g.precision)}</dd>
                          </div>
                          <div>
                            <dt className="inline">{t("recall")}: </dt>
                            <dd className="inline">{pct(g.recall)}</dd>
                          </div>
                          <div>
                            <dt className="inline">{t("labFpRate")}: </dt>
                            <dd className="inline">{pct(g.false_positive_rate)}</dd>
                          </div>
                          <div className="gh-muted">
                            {t("labCounts", { tp: g.tp, fp: g.fp, fn: g.fn, targets: g.targets })}
                          </div>
                        </dl>
                      ) : (
                        "-"
                      )}
                    </td>
                    <td className="align-top text-xs tabular-nums">
                      {s ? (
                        <dl className="space-y-0.5">
                          <div>
                            <dt className="inline">{t("success7d")}: </dt>
                            <dd className="inline">
                              {pct(s.success_rate_7d)} ({s.runs_7d})
                            </dd>
                          </div>
                          <div>
                            <dt className="inline">{t("prodFp")}: </dt>
                            <dd className="inline">
                              {s.triage.false_positive}/{s.triage.groups} (
                              {pct(s.triage.false_positive_rate)})
                            </dd>
                          </div>
                        </dl>
                      ) : (
                        <span className="gh-muted">-</span>
                      )}
                    </td>
                    <td className="align-top">
                      {m.enable_blocked && !m.enabled_global ? (
                        <div className="max-w-56 text-sm">
                          <StatusBadge tone="locked">{t("locked")}</StatusBadge>
                          <span className="mt-1 block text-xs">
                            {t(`blocked.${m.enable_blocked}`)}
                          </span>
                        </div>
                      ) : (
                        <ModuleToggle module={m as AdminModule} />
                      )}
                    </td>
                    <td className="align-top">
                      <ModuleConfig module={m} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Section>
    </>
  );
}
