/**
 * Findings & risk (§8.3): every finding deduplicated by fingerprint (the same finding across
 * scans), with its severity, standard ids (CWE, an indicative CVSS v3.1 vector, CVE/GHSA where the
 * scanner reported them), how often it was seen, what it takes off the score, and the admin's
 * triage (new, verified, accepted risk, false positive, resolved).
 */
import type { Metadata } from "next";
import Link from "next/link";
import { getFormatter, getLocale, getTranslations } from "next-intl/server";
import { HashId, PageHeader, Section, StatusBadge } from "@/components/admin/Stat";
import { TriageControl } from "@/components/admin/TriageControl";
import { SeverityBadge } from "@/components/scan/SeverityBadge";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import { TRIAGE_STATUSES, type FindingGroup, type TriageStatus } from "@/lib/admin-types";
import type { Severity } from "@/lib/types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("adminCenter.nav");
  return { title: t("findings") };
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const CHECK_ID = /^[a-z][a-z0-9_]{1,63}$/;

export default async function AdminFindingsPage({
  searchParams,
}: {
  searchParams: Promise<{ severity?: string; triage?: string; check_id?: string; page?: string }>;
}) {
  const sp = await searchParams;
  const severity = SEVERITIES.includes(sp.severity as Severity)
    ? (sp.severity as Severity)
    : undefined;
  const triage = TRIAGE_STATUSES.includes(sp.triage as TriageStatus)
    ? (sp.triage as TriageStatus)
    : undefined;
  const checkId = sp.check_id && CHECK_ID.test(sp.check_id) ? sp.check_id : undefined;
  const page = Math.max(0, Number.parseInt(sp.page ?? "0", 10) || 0);
  const locale = await getLocale();
  const groups = await loadProtected(() =>
    serverApiFetch<FindingGroup[]>("/admin/findings", {
      query: { severity, triage, check_id: checkId, limit: 50, offset: page * 50, locale },
    }),
  );
  const t = await getTranslations("adminCenter.findings");
  const tc = await getTranslations("adminCenter.common");
  const tSev = await getTranslations("severity");
  const tConsole = await getTranslations("adminCenter.console");
  const format = await getFormatter();
  const when = (v: string) =>
    format.dateTime(new Date(v), { dateStyle: "short", timeStyle: "short", timeZone: "UTC" });
  const query = (extra: Record<string, string>) =>
    `/admin/findings?${new URLSearchParams({
      ...(severity ? { severity } : {}),
      ...(triage ? { triage } : {}),
      ...(checkId ? { check_id: checkId } : {}),
      ...extra,
    })}`;

  return (
    <>
      <PageHeader eyebrow={tConsole("eyebrow")} title={t("title")} intro={t("intro")} />

      <form method="get" className="gh-panel flex flex-wrap items-end gap-3 px-5 py-4 text-sm">
        <div>
          <label htmlFor="f-severity" className="gh-label">
            {t("severityFilter")}
          </label>
          <select
            id="f-severity"
            name="severity"
            defaultValue={severity ?? ""}
            className="gh-input"
          >
            <option value="">{tc("all")}</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {tSev(s)}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor="f-triage" className="gh-label">
            {t("triageFilter")}
          </label>
          <select id="f-triage" name="triage" defaultValue={triage ?? ""} className="gh-input">
            <option value="">{tc("all")}</option>
            {TRIAGE_STATUSES.map((s) => (
              <option key={s} value={s}>
                {t(`triage.${s}`)}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor="f-check" className="gh-label">
            {t("checkFilter")}
          </label>
          <input
            id="f-check"
            name="check_id"
            defaultValue={checkId ?? ""}
            className="gh-input font-mono"
            pattern="[a-z][a-z0-9_]{1,63}"
          />
        </div>
        <button type="submit" className="gh-btn gh-btn-secondary">
          {t("apply")}
        </button>
      </form>

      <Section id="groups-h" title={t("listHeading")} intro={t("cvssNote")}>
        <div className="gh-panel overflow-x-auto">
          <table className="gh-table-admin">
            <caption className="sr-only">{t("listHeading")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("colFinding")}</th>
                <th scope="col">{t("colIds")}</th>
                <th scope="col">{t("colSeen")}</th>
                <th scope="col">{t("colRisk")}</th>
                <th scope="col">{t("colTriage")}</th>
              </tr>
            </thead>
            <tbody>
              {groups.length === 0 ? (
                <tr>
                  <td colSpan={5} className="gh-muted">
                    {tc("none")}
                  </td>
                </tr>
              ) : (
                groups.map((g) => (
                  <tr key={g.fingerprint}>
                    <td className="max-w-md align-top">
                      <SeverityBadge severity={g.severity} />{" "}
                      <span className="font-medium">{g.title}</span>
                      <span className="gh-muted block font-mono text-xs">
                        {g.check_id}/{g.finding_key} · <HashId value={g.fingerprint} />
                      </span>
                      <span className="gh-muted block break-all text-xs">
                        {g.location ?? g.target_url}
                      </span>
                    </td>
                    <td className="align-top text-xs">
                      <span className="block">{g.classification.cwe.join(", ") || "-"}</span>
                      {g.classification.cvss_vector ? (
                        <span className="gh-muted block font-mono">
                          {t("cvss", { score: g.classification.cvss_score ?? 0 })}{" "}
                          <HashId value={g.classification.cvss_vector} chars={12} />
                        </span>
                      ) : null}
                      {[...g.classification.cves, ...g.classification.advisories].length ? (
                        <span className="block font-mono">
                          {[...g.classification.cves, ...g.classification.advisories].join(", ")}
                        </span>
                      ) : null}
                    </td>
                    <td className="whitespace-nowrap align-top text-xs">
                      {t("occurrences", { count: g.occurrences })}
                      <span className="gh-muted block">
                        {when(g.first_seen)} → {when(g.last_seen)}
                      </span>
                      <Link href={`/admin/scans/${g.latest_scan_id}`} className="gh-link">
                        {t("latestScan")}
                      </Link>
                    </td>
                    <td className="align-top text-xs tabular-nums">
                      {t("points", { points: g.score_points })}
                    </td>
                    <td className="align-top">
                      <p className="mb-2">
                        <StatusBadge
                          tone={
                            g.triage === "false_positive"
                              ? "warn"
                              : g.triage === "new"
                                ? "info"
                                : "ok"
                          }
                        >
                          {t(`triage.${g.triage}`)}
                        </StatusBadge>
                      </p>
                      <TriageControl group={g} />
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        <nav aria-label={t("pagination")} className="flex gap-4 text-sm">
          {page > 0 ? (
            <Link className="gh-link" href={query({ page: String(page - 1) })}>
              {tc("previous")}
            </Link>
          ) : null}
          {groups.length === 50 ? (
            <Link className="gh-link" href={query({ page: String(page + 1) })}>
              {tc("next")}
            </Link>
          ) : null}
        </nav>
      </Section>
    </>
  );
}
