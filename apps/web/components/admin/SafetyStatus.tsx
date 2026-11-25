/**
 * Safety status (server component): the security-critical state of the platform in one place,
 * the most prominent block on the overview and the scan orchestration pages. Read-only: it shows
 * the four active-testing locks (founder approval, scanner switch, modules, kill switch), what is
 * effectively on, the lab gates (L passive, M active) and the production false-positive rate. It
 * never hides a lock; a missing source shows "unknown", not "fine".
 */
import { getTranslations } from "next-intl/server";
import type { ActiveTestingState, CenterModule, ModuleStats } from "@/lib/admin-types";
import { StatusBadge, pct, type Tone } from "./Stat";

interface Row {
  key: string;
  label: string;
  tone: Tone;
  value: string;
  detail?: string;
}

function gateSummary(modules: CenterModule[], gate: "L" | "M") {
  const checks = modules.filter((m) => m.is_check && (m.gate?.gate ?? "L") === gate);
  const met = checks.filter((m) => m.gate?.measured && m.gate.meets_gate).length;
  const failed = checks.filter((m) => m.gate?.measured && !m.gate.meets_gate).length;
  return { total: checks.length, met, failed, unmeasured: checks.length - met - failed };
}

export async function SafetyStatus({
  active,
  modules,
  stats,
}: {
  active: ActiveTestingState | null;
  modules: CenterModule[] | null;
  stats: ModuleStats[] | null;
}) {
  const t = await getTranslations("adminCenter.safety");
  const rows: Row[] = [];
  const unknown = (key: string, label: string) =>
    rows.push({ key, label, tone: "neutral", value: t("unknown") });

  if (active) {
    rows.push({
      key: "effective",
      label: t("effective"),
      tone: active.effective === "on" ? "warn" : "ok",
      value: active.effective === "on" ? t("activeOn") : t("activeOff"),
      detail: t("effectiveDetail"),
    });
    rows.push({
      key: "kill",
      label: t("kill"),
      tone: active.global_kill ? "locked" : "neutral",
      value: active.global_kill ? t("killEngaged") : t("killReleased"),
    });
    rows.push({
      key: "approval",
      label: t("approval"),
      tone: active.approved ? "warn" : "locked",
      value: active.approved ? t("approved") : t("awaitingFounder"),
    });
    rows.push({
      key: "scanner",
      label: t("scannerSwitch"),
      tone:
        active.scanner_switch === "on"
          ? "warn"
          : active.scanner_switch === "off"
            ? "locked"
            : "neutral",
      value:
        active.scanner_switch === "on"
          ? t("switchOn")
          : active.scanner_switch === "off"
            ? t("switchOff")
            : t("unknown"),
    });
    rows.push({
      key: "modules",
      label: t("activeModules"),
      tone: active.modules_on.length ? "warn" : "locked",
      value: t("modulesOn", { count: active.modules_on.length }),
      detail: active.modules_on.length ? active.modules_on.join(", ") : undefined,
    });
    rows.push({
      key: "oob",
      label: t("oob"),
      tone: active.oob_configured ? "info" : "locked",
      value: active.oob_configured ? t("oobOn") : t("oobOff"),
    });
  } else {
    for (const k of ["effective", "kill", "approval", "scanner", "modules", "oob"] as const) {
      unknown(k, t(k === "scanner" ? "scannerSwitch" : k === "modules" ? "activeModules" : k));
    }
  }

  if (modules) {
    for (const gate of ["L", "M"] as const) {
      const g = gateSummary(modules, gate);
      rows.push({
        key: `gate-${gate}`,
        label: t(gate === "L" ? "gateL" : "gateM"),
        tone: g.failed ? "crit" : g.unmeasured ? "warn" : "ok",
        value: t("gateMet", { met: g.met, total: g.total }),
        detail: g.failed
          ? t("gateFailed", { count: g.failed })
          : g.unmeasured
            ? t("gateUnmeasured", { count: g.unmeasured })
            : undefined,
      });
    }
  } else {
    unknown("gate-L", t("gateL"));
    unknown("gate-M", t("gateM"));
  }

  if (stats) {
    const groups = stats.reduce((n, s) => n + s.triage.groups, 0);
    const fp = stats.reduce((n, s) => n + s.triage.false_positive, 0);
    const rate = groups ? fp / groups : null;
    rows.push({
      key: "fp",
      label: t("prodFp"),
      tone: rate === null ? "neutral" : rate <= 0.05 ? "ok" : "warn",
      value: rate === null ? t("noTriage") : pct(rate),
      detail: rate === null ? undefined : t("fpDetail", { fp, groups }),
    });
  } else {
    unknown("fp", t("prodFp"));
  }

  return (
    <section
      aria-labelledby="safety-h"
      className="gh-panel border-l-4 border-l-navy-800 dark:border-l-teal-300"
    >
      <div className="gh-panel-head">
        <div>
          <h2 id="safety-h" className="text-base font-semibold">
            {t("title")}
          </h2>
          <p className="gh-muted mt-0.5 text-xs">{t("intro")}</p>
        </div>
        <StatusBadge
          size="lg"
          tone={active ? (active.effective === "on" ? "warn" : "ok") : "neutral"}
        >
          {active ? (active.effective === "on" ? t("headlineOn") : t("headlineOff")) : t("unknown")}
        </StatusBadge>
      </div>
      <dl className="grid gap-px bg-slate-200 sm:grid-cols-2 lg:grid-cols-3 dark:bg-navy-800">
        {rows.map((r) => (
          <div key={r.key} className="bg-white px-5 py-3 dark:bg-navy-900">
            <dt className="gh-eyebrow">{r.label}</dt>
            <dd className="mt-1.5">
              <StatusBadge tone={r.tone}>{r.value}</StatusBadge>
              {r.detail ? <span className="gh-muted mt-1 block text-xs">{r.detail}</span> : null}
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
