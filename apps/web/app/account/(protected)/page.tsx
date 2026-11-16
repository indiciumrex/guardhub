/**
 * Account home: the user's projects with their latest scan, plus "add project".
 */
import type { Metadata } from "next";
import Link from "next/link";
import { getFormatter, getTranslations } from "next-intl/server";
import { AddProjectForm } from "@/components/account/AddProjectForm";
import { ScanStatusBadge } from "@/components/account/ScanStatusBadge";
import { SeverityCounts } from "@/components/scan/SeverityCounts";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import type { Project } from "@/lib/types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("account");
  return { title: t("title") };
}

export default async function AccountHomePage() {
  const projects = await loadProtected(() => serverApiFetch<Project[]>("/projects"));
  const t = await getTranslations("account");
  const format = await getFormatter();

  return (
    <div className="space-y-10">
      <div>
        <h1 className="text-3xl font-bold">{t("title")}</h1>
        <p className="gh-muted mt-2">{t("intro")}</p>
      </div>

      <section aria-labelledby="projects-heading">
        <h2 id="projects-heading" className="text-xl font-semibold">
          {t("projectsHeading")}
        </h2>
        {projects.length === 0 ? (
          <p className="gh-muted mt-4">{t("noProjects")}</p>
        ) : (
          <ul className="mt-4 grid gap-4 md:grid-cols-2">
            {projects.map((project) => (
              <li key={project.id} className="gh-card p-5">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <h3 className="text-lg font-semibold">
                    <Link href={`/account/projects/${project.id}`} className="gh-link">
                      {project.name}
                    </Link>
                  </h3>
                  <span
                    className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold ${
                      project.verified
                        ? "border-emerald-300 text-emerald-800 dark:border-emerald-700 dark:text-emerald-200"
                        : "border-amber-300 text-amber-900 dark:border-amber-700 dark:text-amber-200"
                    }`}
                  >
                    {project.verified ? t("verified") : t("notVerified")}
                  </span>
                </div>
                <p className="gh-muted mt-1 break-all text-sm">{project.target_url}</p>
                {project.last_scan ? (
                  <div className="mt-4 space-y-2 text-sm">
                    <p>
                      {t("lastScan", {
                        date: format.dateTime(new Date(project.last_scan.created_at), {
                          dateStyle: "medium",
                          timeZone: "UTC",
                        }),
                      })}{" "}
                      {project.last_scan.score !== null
                        ? t("scoreValue", { score: project.last_scan.score })
                        : null}
                    </p>
                    <div className="flex flex-wrap items-center gap-2">
                      <ScanStatusBadge status={project.last_scan.status} />
                      <SeverityCounts counts={project.last_scan.finding_counts} compact />
                    </div>
                  </div>
                ) : (
                  <p className="gh-muted mt-4 text-sm">{t("neverScanned")}</p>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-labelledby="add-heading" className="gh-card max-w-2xl p-6">
        <h2 id="add-heading" className="text-xl font-semibold">
          {t("addHeading")}
        </h2>
        <p className="gh-muted mt-1 text-sm">{t("addIntro")}</p>
        <div className="mt-4">
          <AddProjectForm />
        </div>
      </section>
    </div>
  );
}
