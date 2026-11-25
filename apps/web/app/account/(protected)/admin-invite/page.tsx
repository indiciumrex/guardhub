/**
 * Accept an admin invitation (Prompt 2 §5). The page is behind sign-in; the API accepts only for
 * the invited e-mail, signed in with two-factor, once. It never changes a role by itself.
 */
import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { AcceptAdminInvite } from "@/components/admin/PeopleControls";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("adminInvite");
  return { title: t("title"), robots: { index: false } };
}

export default async function AdminInvitePage({
  searchParams,
}: {
  searchParams: Promise<{ token?: string }>;
}) {
  const token = (await searchParams).token ?? "";
  const t = await getTranslations("adminInvite");
  return (
    <div className="gh-container max-w-2xl space-y-4 py-10">
      <h1 className="text-2xl font-bold tracking-tight">{t("title")}</h1>
      <p className="gh-muted">{t("intro")}</p>
      <ul className="list-disc space-y-1 pl-5 text-sm">
        <li>{t("ruleEmail")}</li>
        <li>{t("ruleMfa")}</li>
        <li>{t("ruleOnce")}</li>
      </ul>
      {token ? <AcceptAdminInvite token={token} /> : <p role="alert">{t("noToken")}</p>}
    </div>
  );
}
