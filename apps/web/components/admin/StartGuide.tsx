/**
 * First-use guide for admins (profile prompt item 4): add a site → prove ownership → scan, with
 * each step's state computed from the admin's own data (their projects and verified sites). Until
 * all three are done it leads the console; afterwards it shrinks to one line with "New scan".
 */
import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { Panel, StatusBadge } from "@/components/admin/Stat";
import { serverApiFetch } from "@/lib/api-server";
import type { SiteRow } from "@/lib/admin-types";
import type { Project } from "@/lib/types";

export async function StartGuide() {
  const [projectsR, sitesR] = await Promise.allSettled([
    serverApiFetch<Project[]>("/projects"),
    serverApiFetch<SiteRow[]>("/admin/sites"),
  ]);
  if (projectsR.status !== "fulfilled" || sitesR.status !== "fulfilled") return null;
  const projects = projectsR.value;
  const sites = sitesR.value;
  const t = await getTranslations("startGuide");
  const steps = [
    { key: "add", done: sites.length > 0 || projects.length > 0, href: "/account/new-scan#add-h" },
    {
      key: "verify",
      done: sites.some((s) => s.status === "verified"),
      href: sites.length ? "/admin/sites" : "/account/new-scan#add-h",
    },
    { key: "scan", done: projects.some((p) => p.last_scan), href: "/account/new-scan" },
  ] as const;
  const next = steps.find((s) => !s.done);

  if (!next) {
    return (
      <div className="gh-panel flex flex-wrap items-center justify-between gap-3 px-5 py-3">
        <p className="flex items-center gap-2 text-sm">
          <StatusBadge tone="ok">{t("ready")}</StatusBadge>
          <span>{t("readyHelp")}</span>
        </p>
        <Link href="/account/new-scan" className="gh-btn-primary min-h-9 px-3 py-1.5 text-sm">
          {t("newScan")}
        </Link>
      </div>
    );
  }
  return (
    <Panel
      id="start-h"
      title={t("title")}
      intro={t("intro")}
      emphasis="info"
      actions={
        <Link href={next.href} className="gh-btn-primary min-h-9 px-3 py-1.5 text-sm">
          {t(`${next.key}.cta`)}
        </Link>
      }
    >
      <ol aria-label={t("title")} className="grid gap-3 sm:grid-cols-3">
        {steps.map((s, i) => (
          <li
            key={s.key}
            className={`rounded-lg border p-3 ${
              s.key === next.key
                ? "border-sky-400 dark:border-sky-600"
                : "border-slate-200 dark:border-navy-800"
            }`}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="text-sm font-semibold">
                {i + 1}. {t(`${s.key}.title`)}
              </span>
              <StatusBadge tone={s.done ? "ok" : "neutral"}>
                {s.done ? t("done") : t("todo")}
              </StatusBadge>
            </div>
            <p className="gh-muted mt-1 text-xs">{t(`${s.key}.help`)}</p>
          </li>
        ))}
      </ol>
    </Panel>
  );
}
