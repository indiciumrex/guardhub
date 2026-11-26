"use client";
/**
 * Verified sites (profile prompt, item 2): every site this admin has proven, its status
 * (verified / expired / failed / pending), the last proof and the last check, and a one-click
 * re-verify that runs the normal ownership proof. Nothing here grants a scan (§9.2).
 */
import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useFormatter, useTranslations } from "next-intl";
import { StatusBadge, type Tone } from "@/components/admin/Stat";
import { apiFetch } from "@/lib/api";
import type { SiteRow, SiteStatus } from "@/lib/admin-types";
import { useErrorMessage } from "@/lib/use-error-message";

export const SITE_TONE: Record<SiteStatus, Tone> = {
  verified: "ok",
  expired: "warn",
  failed: "crit",
  pending: "info",
};

export function VerifiedSitesTable({ sites }: { sites: SiteRow[] }) {
  const t = useTranslations("sites");
  const format = useFormatter();
  const errorMessage = useErrorMessage();
  const router = useRouter();
  const [busy, setBusy] = useState<string | null>(null);
  const [messages, setMessages] = useState<Record<string, { text: string; ok: boolean }>>({});
  const when = (v: string | null) =>
    v
      ? format.dateTime(new Date(v), { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" })
      : t("never");

  async function reverify(row: SiteRow) {
    const key = `${row.source}:${row.id}`;
    setBusy(key);
    try {
      const rows = await apiFetch<SiteRow[]>(`/admin/sites/${row.source}/${row.id}/reverify`, {
        method: "POST",
      });
      const after = rows.find((r) => r.source === row.source && r.id === row.id);
      setMessages((m) => ({
        ...m,
        [key]: {
          text: t("reverified", { status: t(`status.${after?.status ?? "verified"}`) }),
          ok: true,
        },
      }));
      router.refresh();
    } catch (err) {
      setMessages((m) => ({ ...m, [key]: { text: errorMessage(err), ok: false } }));
      router.refresh();
    } finally {
      setBusy(null);
    }
  }

  if (sites.length === 0) {
    return (
      <p className="text-sm">
        {t("empty")}{" "}
        <Link href="/admin/trusted-domains" className="gh-link">
          {t("addDomain")}
        </Link>
      </p>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="gh-table-admin min-w-[56rem]">
        <caption className="sr-only">{t("title")}</caption>
        <thead>
          <tr>
            <th scope="col">{t("colSite")}</th>
            <th scope="col">{t("colStatus")}</th>
            <th scope="col">{t("colSource")}</th>
            <th scope="col">{t("colLastVerified")}</th>
            <th scope="col">{t("colLastChecked")}</th>
            <th scope="col">
              <span className="sr-only">{t("colActions")}</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {sites.map((row) => {
            const key = `${row.source}:${row.id}`;
            const msg = messages[key];
            return (
              <tr key={key}>
                <th scope="row" className="text-sm font-medium">
                  <span className="font-mono">{row.host}</span>
                  {row.name && row.name !== row.host ? (
                    <span className="gh-muted block text-xs font-normal">{row.name}</span>
                  ) : null}
                </th>
                <td>
                  <StatusBadge tone={SITE_TONE[row.status]}>
                    {t(`status.${row.status}`)}
                  </StatusBadge>
                  {row.status !== "verified" && row.last_error ? (
                    <span className="gh-muted mt-1 block text-xs">
                      {t.has(`reason.${row.last_error}`)
                        ? t(`reason.${row.last_error}`)
                        : row.last_error}
                    </span>
                  ) : null}
                </td>
                <td className="text-sm">
                  {t(`source.${row.source}`)}
                  {row.source === "trusted_domain" && row.project_ids.length ? (
                    <span className="gh-muted block text-xs">
                      {t("linkedProjects", { count: row.project_ids.length })}
                    </span>
                  ) : null}
                </td>
                <td className="text-sm">{when(row.last_verified_at)}</td>
                <td className="text-sm">{when(row.last_checked_at)}</td>
                <td>
                  <button
                    type="button"
                    className={row.status === "verified" ? "gh-btn-secondary" : "gh-btn-primary"}
                    disabled={busy !== null}
                    aria-label={t("reverifyNamed", { host: row.host })}
                    onClick={() => void reverify(row)}
                  >
                    {busy === key ? t("checking") : t("reverify")}
                  </button>
                  {msg ? (
                    <p
                      role={msg.ok ? "status" : "alert"}
                      className={`mt-1 text-xs ${msg.ok ? "text-emerald-800 dark:text-emerald-200" : "text-red-800 dark:text-red-200"}`}
                    >
                      {msg.text}
                    </p>
                  ) : null}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
