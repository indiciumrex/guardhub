/**
 * Admin: users (§8.3). Plain admin/customer split; the role is enforced by the API (RLS + admin
 * session), never by this page.
 */
import type { Metadata } from "next";
import { getFormatter, getTranslations } from "next-intl/server";
import { serverApiFetch } from "@/lib/api-server";
import { loadProtected } from "@/lib/auth-server";
import { listItems, type ListPayload, type User } from "@/lib/types";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("admin");
  return { title: t("usersHeading") };
}

export default async function AdminUsersPage() {
  const users = await loadProtected(() =>
    serverApiFetch<ListPayload<User>>("/admin/users", { query: { limit: 200, offset: 0 } }),
  );
  const t = await getTranslations("admin");
  const format = await getFormatter();
  const formatDate = (value: string) =>
    format.dateTime(new Date(value), { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" });

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">{t("usersHeading")}</h1>
      <div className="gh-panel overflow-x-auto">
        <table className="gh-table-admin">
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
    </div>
  );
}
