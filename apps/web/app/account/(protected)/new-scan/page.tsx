/**
 * New scan (profile prompt item 4): the one place to start a scan, one click from every page.
 * 1. Scan a verified site (one click). 2. Sites still waiting for their ownership proof.
 * 3. Add a new site: add → verify → scan. Admins also see their trusted domains and the other
 * scan types (owner active scan, observe-only for super-admins, repositories).
 * Nothing here skips §9.2: every scan proves ownership again in the API.
 */
import type { Metadata } from "next";
import Link from "next/link";
import { getFormatter, getTranslations } from "next-intl/server";
import { AddProjectForm } from "@/components/account/AddProjectForm";
import { PageHeader, Panel, StatusBadge } from "@/components/admin/Stat";
import { ScanNowButton } from "@/components/scan/ScanNowButton";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected, requireUser } from "@/lib/auth-server";
import type { Project, TrustedDomain } from "@/lib/types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("newScan");
  return { title: t("title") };
}

export default async function NewScanPage() {
  const user = await requireUser();
  const isAdmin = user.role === "admin";
  const projects = await loadProtected(() => serverApiFetch<Project[]>("/projects"));
  const [domainsR, observeR] = isAdmin
    ? await Promise.allSettled([
        serverApiFetch<TrustedDomain[]>("/admin/trusted-domains"),
        serverApiFetch<unknown>("/admin/observe-scans"),
      ])
    : [null, null];
  const t = await getTranslations("newScan");
  const tAccount = await getTranslations("account");
  const format = await getFormatter();
  const when = (v: string) =>
    format.dateTime(new Date(v), { dateStyle: "medium", timeZone: "UTC" });

  const ready = projects.filter((p) => p.verified);
  const waiting = projects.filter((p) => !p.verified);
  const origins = new Set(projects.map((p) => p.target_url));
  const domainsOnly =
    domainsR?.status === "fulfilled"
      ? domainsR.value.filter((d) => d.status === "active" && !origins.has(d.target_origin))
      : [];
  const superAdmin = observeR?.status === "fulfilled";

  return (
    <>
      <PageHeader eyebrow={t("eyebrow")} title={t("title")} intro={t("intro")} />

      <ol aria-label={t("flowLabel")} className="grid gap-3 sm:grid-cols-3">
        {(["add", "verify", "scan"] as const).map((k, i) => (
          <li key={k} className="gh-panel px-4 py-3">
            <p className="gh-eyebrow">{t("stepN", { n: i + 1 })}</p>
            <p className="mt-1 font-semibold">{t(`flow.${k}.title`)}</p>
            <p className="gh-muted mt-0.5 text-xs">{t(`flow.${k}.help`)}</p>
          </li>
        ))}
      </ol>

      <Panel
        id="ready-h"
        title={t("readyTitle")}
        intro={t("readyIntro")}
        emphasis={ready.length || domainsOnly.length ? "ok" : undefined}
      >
        {ready.length === 0 && domainsOnly.length === 0 ? (
          <p className="text-sm">{t("noneReady")}</p>
        ) : (
          <ul className="divide-y divide-slate-200 dark:divide-navy-800">
            {ready.map((p) => (
              <li key={p.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
                <div className="min-w-0">
                  <Link href={`/account/projects/${p.id}`} className="gh-link font-semibold">
                    {p.name}
                  </Link>
                  <p className="gh-muted text-xs break-all">{p.target_url}</p>
                  <p className="mt-1 flex flex-wrap items-center gap-2 text-xs">
                    <StatusBadge tone="ok">{tAccount("verified")}</StatusBadge>
                    {p.last_scan ? (
                      <Link href={`/account/scans/${p.last_scan.id}`} className="gh-link">
                        {t("lastScan", { when: when(p.last_scan.created_at) })}
                      </Link>
                    ) : (
                      <span className="gh-muted">{tAccount("neverScanned")}</span>
                    )}
                  </p>
                </div>
                <ScanNowButton
                  path={`/projects/${p.id}/scans`}
                  label={t("scanNamed", { name: p.name })}
                />
              </li>
            ))}
            {domainsOnly.map((d) => (
              <li key={d.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
                <div className="min-w-0">
                  <p className="font-mono font-semibold">{d.host}</p>
                  <p className="mt-1 text-xs">
                    <StatusBadge tone="ok">{t("trustedDomain")}</StatusBadge>
                  </p>
                </div>
                <ScanNowButton
                  path={`/admin/trusted-domains/${d.id}/scan`}
                  label={t("scanNamed", { name: d.host })}
                />
              </li>
            ))}
          </ul>
        )}
      </Panel>

      {waiting.length ? (
        <Panel id="waiting-h" title={t("waitingTitle")} intro={t("waitingIntro")} emphasis="warn">
          <ul className="divide-y divide-slate-200 dark:divide-navy-800">
            {waiting.map((p) => (
              <li key={p.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
                <div className="min-w-0">
                  <p className="font-semibold">{p.name}</p>
                  <p className="gh-muted text-xs break-all">{p.target_url}</p>
                </div>
                <Link
                  href={`/account/projects/${p.id}`}
                  className="gh-btn-secondary min-h-10 px-3 py-1.5"
                  aria-label={t("verifyNamed", { name: p.name })}
                >
                  {t("verify")}
                </Link>
              </li>
            ))}
          </ul>
        </Panel>
      ) : null}

      <Panel id="add-h" title={t("addTitle")} intro={t("addIntro")}>
        <AddProjectForm />
      </Panel>

      <Panel id="more-h" title={t("moreTitle")}>
        <ul className="grid gap-3 text-sm sm:grid-cols-2">
          <li className="rounded-lg border border-slate-200 p-3 dark:border-navy-800">
            <Link href="/account#github" className="gh-link font-semibold">
              {t("more.repo.title")}
            </Link>
            <p className="gh-muted mt-1 text-xs">{t("more.repo.help")}</p>
          </li>
          <li className="rounded-lg border border-slate-200 p-3 dark:border-navy-800">
            <Link href="/scan" className="gh-link font-semibold">
              {t("more.quick.title")}
            </Link>
            <p className="gh-muted mt-1 text-xs">{t("more.quick.help")}</p>
          </li>
          {isAdmin ? (
            <>
              <li className="rounded-lg border border-slate-200 p-3 dark:border-navy-800">
                <Link href="/admin/trusted-domains" className="gh-link font-semibold">
                  {t("more.trusted.title")}
                </Link>
                <p className="gh-muted mt-1 text-xs">{t("more.trusted.help")}</p>
              </li>
              <li className="rounded-lg border border-slate-200 p-3 dark:border-navy-800">
                <Link href="/admin/scans#owner-scan" className="gh-link font-semibold">
                  {t("more.active.title")}
                </Link>
                <p className="gh-muted mt-1 text-xs">{t("more.active.help")}</p>
              </li>
              {superAdmin ? (
                <li className="rounded-lg border border-slate-200 p-3 dark:border-navy-800">
                  <Link href="/admin/observe" className="gh-link font-semibold">
                    {t("more.observe.title")}
                  </Link>
                  <p className="gh-muted mt-1 text-xs">{t("more.observe.help")}</p>
                </li>
              ) : null}
            </>
          ) : null}
        </ul>
      </Panel>
    </>
  );
}
