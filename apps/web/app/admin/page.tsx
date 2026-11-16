/**
 * Minimal admin panel (§8.3 MVP): module toggles, users, scans, system health and the
 * AI seam status. Each section loads independently, so one failing endpoint doesn't hide
 * the others.
 */
import type { Metadata } from "next";
import { getFormatter, getTranslations } from "next-intl/server";
import { ScanStatusBadge } from "@/components/account/ScanStatusBadge";
import { ModuleToggle } from "@/components/admin/ModuleToggle";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import {
  listItems,
  type AdminModule,
  type AiStatus,
  type HealthCheck,
  type HealthResponse,
  type ListPayload,
  type ScanSummary,
  type User,
} from "@/lib/types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("admin");
  return { title: t("title") };
}

const PAGE = { limit: 50, offset: 0 };

function settled<T>(result: PromiseSettledResult<T>): T | null {
  return result.status === "fulfilled" ? result.value : null;
}

export default async function AdminPage() {
  const [modulesR, usersR, scansR, healthR, moduleHealthR, aiR] = await loadProtected(() =>
    Promise.allSettled([
      serverApiFetch<AdminModule[]>("/admin/modules"),
      serverApiFetch<ListPayload<User>>("/admin/users", { query: PAGE }),
      serverApiFetch<ListPayload<ScanSummary>>("/admin/scans", { query: PAGE }),
      serverApiFetch<HealthResponse>("/health"),
      serverApiFetch<ListPayload<HealthCheck>>("/admin/health"),
      serverApiFetch<AiStatus>("/admin/ai"),
    ]),
  );
  const modules = settled(modulesR);
  const users = settled(usersR);
  const scans = settled(scansR);
  const health = settled(healthR);
  const moduleHealth = settled(moduleHealthR);
  const ai = settled(aiR);

  const t = await getTranslations("admin");
  const tHealth = await getTranslations("health");
  const format = await getFormatter();
  const formatDate = (value: string) =>
    format.dateTime(new Date(value), { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" });
  const unavailable = <p className="gh-muted text-sm">{t("unavailable")}</p>;
  const healthLabel = (status: string) => (tHealth.has(status) ? tHealth(status) : status);

  return (
    <div className="space-y-10">
      <h1 className="text-3xl font-bold">{t("title")}</h1>

      <section aria-labelledby="health-heading" className="grid gap-4 md:grid-cols-2">
        <div className="gh-card p-5">
          <h2 id="health-heading" className="text-lg font-semibold">
            {t("healthHeading")}
          </h2>
          {health ? (
            <dl className="mt-3 space-y-1 text-sm">
              <div className="flex justify-between gap-3">
                <dt className="font-semibold">{t("overall")}</dt>
                <dd>{healthLabel(health.status)}</dd>
              </div>
              {Object.entries(health.components).map(([name, status]) => (
                <div key={name} className="flex justify-between gap-3">
                  <dt>{name}</dt>
                  <dd>{healthLabel(status)}</dd>
                </div>
              ))}
            </dl>
          ) : (
            unavailable
          )}
        </div>
        <div className="gh-card p-5">
          <h2 className="text-lg font-semibold">{t("aiHeading")}</h2>
          {ai ? (
            <p className="mt-3 text-sm">
              {ai.active ? t("aiActive", { provider: ai.provider ?? "-" }) : t("aiNotConfigured")}
            </p>
          ) : (
            unavailable
          )}
        </div>
      </section>

      <section aria-labelledby="modules-heading">
        <h2 id="modules-heading" className="text-xl font-semibold">
          {t("modulesHeading")}
        </h2>
        <p className="gh-muted mt-1 text-sm">{t("modulesIntro")}</p>
        {modules ? (
          <div className="gh-card mt-4 overflow-x-auto">
            <table className="gh-table">
              <caption className="sr-only">{t("modulesHeading")}</caption>
              <thead>
                <tr>
                  <th scope="col">{t("colModule")}</th>
                  <th scope="col">{t("colCategory")}</th>
                  <th scope="col">{t("colPlan")}</th>
                  <th scope="col">{t("colHealth")}</th>
                  <th scope="col">{t("colEnabled")}</th>
                </tr>
              </thead>
              <tbody>
                {modules.map((module) => {
                  const check = listItems(moduleHealth).find((h) => h.module_key === module.key);
                  return (
                    <tr key={module.key}>
                      <th scope="row" className="font-medium">
                        {module.name}
                        <span className="gh-muted block font-mono text-xs font-normal">
                          {module.key}
                        </span>
                      </th>
                      <td>{module.category}</td>
                      <td>{module.min_plan}</td>
                      <td>
                        {check ? (
                          <>
                            {healthLabel(check.status)}
                            {check.latency_ms !== null ? (
                              <span className="gh-muted block text-xs">
                                {t("latency", { ms: check.latency_ms })}
                              </span>
                            ) : null}
                          </>
                        ) : (
                          <span className="gh-muted">{t("noData")}</span>
                        )}
                      </td>
                      <td>
                        <ModuleToggle module={module} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          unavailable
        )}
      </section>

      <section aria-labelledby="users-heading">
        <h2 id="users-heading" className="text-xl font-semibold">
          {t("usersHeading")}
        </h2>
        {users ? (
          <div className="gh-card mt-4 overflow-x-auto">
            <table className="gh-table">
              <caption className="sr-only">{t("usersHeading")}</caption>
              <thead>
                <tr>
                  <th scope="col">{t("colEmail")}</th>
                  <th scope="col">{t("colRole")}</th>
                  <th scope="col">{t("colTwoFactor")}</th>
                  <th scope="col">{t("colLocale")}</th>
                  <th scope="col">{t("colCreated")}</th>
                </tr>
              </thead>
              <tbody>
                {listItems(users).map((user) => (
                  <tr key={user.id}>
                    <td className="break-all">{user.email}</td>
                    <td>{t(`roles.${user.role}`)}</td>
                    <td>{user.totp_enabled ? t("yes") : t("no")}</td>
                    <td>{user.locale}</td>
                    <td className="whitespace-nowrap">{formatDate(user.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          unavailable
        )}
      </section>

      <section aria-labelledby="scans-heading">
        <h2 id="scans-heading" className="text-xl font-semibold">
          {t("scansHeading")}
        </h2>
        {scans ? (
          <div className="gh-card mt-4 overflow-x-auto">
            <table className="gh-table">
              <caption className="sr-only">{t("scansHeading")}</caption>
              <thead>
                <tr>
                  <th scope="col">{t("colTarget")}</th>
                  <th scope="col">{t("colStatus")}</th>
                  <th scope="col">{t("colScore")}</th>
                  <th scope="col">{t("colCreated")}</th>
                </tr>
              </thead>
              <tbody>
                {listItems(scans).map((scan) => (
                  <tr key={scan.id}>
                    <td className="break-all">{scan.target_url}</td>
                    <td>
                      <ScanStatusBadge status={scan.status} />
                    </td>
                    <td className="tabular-nums">{scan.score ?? "-"}</td>
                    <td className="whitespace-nowrap">{formatDate(scan.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          unavailable
        )}
      </section>
    </div>
  );
}
