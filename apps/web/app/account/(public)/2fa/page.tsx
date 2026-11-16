/**
 * 2FA step after login/registration. Needs a (pre-MFA) session; a complete session goes
 * straight on. Mode: the `mode` hint from login, else derived from `totp_enabled`.
 */
import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { getTranslations } from "next-intl/server";
import { AuthCard } from "@/components/account/AuthCard";
import { TwoFactorForm } from "@/components/account/TwoFactorForm";
import { getSessionUser } from "@/lib/auth-server";
import { loginUrl, safeNextPath } from "@/lib/navigation";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("twoFactor");
  return { title: t("title"), robots: { index: false } };
}

export default async function TwoFactorPage({
  searchParams,
}: {
  searchParams: Promise<{ next?: string | string[]; mode?: string | string[] }>;
}) {
  const params = await searchParams;
  const next = safeNextPath(typeof params.next === "string" ? params.next : undefined);
  const user = await getSessionUser();
  if (!user) redirect(loginUrl(next));
  if (user.mfa_complete) redirect(next);

  const hinted = params.mode === "setup" || params.mode === "verify" ? params.mode : null;
  const mode = hinted ?? (user.totp_enabled ? "verify" : "setup");
  const t = await getTranslations("twoFactor");
  return (
    <AuthCard title={t("title")} intro={mode === "setup" ? t("setupIntro") : t("verifyIntro")}>
      <TwoFactorForm mode={mode} next={next} />
    </AuthCard>
  );
}
