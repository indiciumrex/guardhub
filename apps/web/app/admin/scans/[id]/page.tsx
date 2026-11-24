/**
 * One scan for the admin: lifecycle, ownership proof, actions, and its score explained
 * (100 minus a fixed weight per finding by severity; the same formula that computed it).
 */
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { getFormatter, getLocale, getTranslations } from "next-intl/server";
import { ScanActions } from "@/components/admin/ScanActions";
import { Badge, Section } from "@/components/admin/Stat";
import { SeverityBadge } from "@/components/scan/SeverityBadge";
import { ApiError } from "@/lib/api";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import type { AdminScan, RiskView } from "@/lib/admin-types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("adminCenter.scans");
  return { title: t("detailTitle") };
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export default async function AdminScanPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!UUID.test(id)) notFound();
  const locale = await getLocale();
  let data: [AdminScan, RiskView];
  try {
    data = await loadProtected(() =>
      Promise.all([
        serverApiFetch<AdminScan>(`/admin/scans/${id}`),
        serverApiFetch<RiskView>(`/admin/scans/${id}/risk`, { query: { locale } }),
      ]),
    );
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) notFound();
    throw err;
  }
  const [scan, risk] = data;
  const t = await getTranslations("adminCenter.scans");
  const tc = await getTranslations("adminCenter.common");
  const tSev = await getTranslations("severity");
  const format = await getFormatter();
  const when = (v: string | null) =>
    v
      ? format.dateTime(new Date(v), { dateStyle: "medium", timeStyle: "medium", timeZone: "UTC" })
      : "-";

  return (
    <div className="space-y-8">
      <div>
        <Link href="/admin/scans" className="gh-link text-sm">
          {t("back")}
        </Link>
        <h1 className="mt-2 break-all text-3xl font-bold">{scan.target_url}</h1>
        <p className="gh-muted mt-1 font-mono text-xs">{scan.id}</p>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <div className="gh-card p-5 text-sm">
          <dl className="space-y-1">
            <div className="flex justify-between gap-3">
              <dt>{t("colLifecycle")}</dt>
              <dd>{tc(`lifecycle.${scan.lifecycle}`)}</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt>{t("created")}</dt>
              <dd>{when(scan.created_at)}</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt>{t("started")}</dt>
              <dd>{when(scan.started_at)}</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt>{t("finished")}</dt>
              <dd>{when(scan.finished_at)}</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt>{t("colProof")}</dt>
              <dd>
                {t(`proof.${scan.ownership.kind}`)}
                {scan.ownership.method ? ` · ${t(`method.${scan.ownership.method}`)}` : ""}
              </dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt>{t("verifiedAt")}</dt>
              <dd>{when(scan.ownership.verified_at)}</dd>
            </div>
          </dl>
          <div className="mt-4">
            <ScanActions scan={scan} />
          </div>
        </div>
        <div className="gh-card p-5">
          <h2 className="text-lg font-semibold">{t("riskHeading")}</h2>
          <p className="mt-2 text-4xl font-bold tabular-nums">
            {risk.score ?? "-"}
            <span className="gh-muted text-base font-normal">/100</span>
          </p>
          <p className="gh-muted mt-2 text-sm">{t("riskFormula")}</p>
          <p className="mt-1 text-xs">
            {t("weights")}:{" "}
            {Object.entries(risk.weights)
              .map(([s, w]) => `${tSev(s)} ${w}`)
              .join(" · ")}
          </p>
          {risk.capped_at_zero ? (
            <p className="mt-2 text-sm">
              <Badge tone="bad">{t("cappedAtZero")}</Badge>
            </p>
          ) : null}
        </div>
      </div>

      <Section id="contrib-h" title={t("contributionsHeading")}>
        <div className="gh-card overflow-x-auto">
          <table className="gh-table">
            <caption className="sr-only">{t("contributionsHeading")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("severityCol")}</th>
                <th scope="col">{t("countCol")}</th>
                <th scope="col">{t("weightCol")}</th>
                <th scope="col">{t("pointsCol")}</th>
              </tr>
            </thead>
            <tbody>
              {risk.contributions.map((c) => (
                <tr key={c.severity}>
                  <th scope="row">
                    <SeverityBadge severity={c.severity} />
                  </th>
                  <td className="tabular-nums">{c.count}</td>
                  <td className="tabular-nums">{c.weight}</td>
                  <td className="tabular-nums">−{c.points}</td>
                </tr>
              ))}
              <tr>
                <th scope="row">{t("result")}</th>
                <td colSpan={3} className="font-semibold tabular-nums">
                  max(0, 100 − {risk.contributions.reduce((n, c) => n + c.points, 0)}) ={" "}
                  {risk.recomputed}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <ul className="gh-card divide-y divide-slate-200 text-sm dark:divide-navy-700">
          {risk.findings.map((f, i) => (
            <li key={`${f.check_id}-${f.finding_key}-${i}`} className="flex flex-wrap gap-2 p-3">
              <SeverityBadge severity={f.severity} />
              <span>{f.title}</span>
              <span className="gh-muted font-mono text-xs">
                {f.check_id}/{f.finding_key} · {f.cwe.join(", ") || "-"} · −{f.points}
              </span>
            </li>
          ))}
        </ul>
      </Section>
    </div>
  );
}
