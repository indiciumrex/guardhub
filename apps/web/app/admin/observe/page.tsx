/**
 * Observe-only scan without an ownership proof (profile prompt item 3). Super-admins only: the API
 * answers 404 to everyone else, which this page passes on. The server switch is off by default;
 * the page then explains the boundary and nothing can be started.
 */
import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { ObserveScanForm } from "@/components/admin/ObserveScan";
import { PageHeader, Panel, StatusBadge } from "@/components/admin/Stat";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import type { ObserveReadiness } from "@/lib/admin-types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("observe");
  return { title: t("title") };
}

export default async function ObserveScanPage() {
  const readiness = await loadProtected(() =>
    serverApiFetch<ObserveReadiness>("/admin/observe-scans"),
  );
  const t = await getTranslations("observe");
  const tConsole = await getTranslations("adminCenter.console");
  const tChecks = await getTranslations("checks");
  const name = (c: string) => (tChecks.has(`${c}.name`) ? tChecks(`${c}.name`) : c);
  return (
    <>
      <PageHeader eyebrow={tConsole("eyebrow")} title={t("title")} intro={t("intro")} />
      <Panel
        id="observe-boundary-h"
        title={t("boundaryTitle")}
        emphasis="locked"
        actions={
          readiness.enabled ? (
            <StatusBadge tone="warn">{t("on")}</StatusBadge>
          ) : (
            <StatusBadge tone="locked">{t("off")}</StatusBadge>
          )
        }
      >
        <div className="grid gap-4 text-sm md:grid-cols-2">
          <div>
            <p className="font-semibold">{t("allowedTitle")}</p>
            <ul className="mt-1 list-disc pl-5">
              {readiness.checks.map((c) => (
                <li key={c}>{name(c)}</li>
              ))}
            </ul>
          </div>
          <div>
            <p className="font-semibold">{t("needsProofTitle")}</p>
            <ul className="mt-1 list-disc pl-5">
              {readiness.needs_verified_site.map((c) => (
                <li key={c}>{name(c)}</li>
              ))}
            </ul>
          </div>
        </div>
        {!readiness.enabled ? <p className="mt-4 text-sm">{t("offHelp")}</p> : null}
      </Panel>
      <Panel id="observe-form-h" title={t("formLabel")}>
        <ObserveScanForm readiness={readiness} />
      </Panel>
    </>
  );
}
