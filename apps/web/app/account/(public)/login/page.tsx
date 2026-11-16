import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { AuthCard } from "@/components/account/AuthCard";
import { LoginForm } from "@/components/account/LoginForm";
import { safeNextPath } from "@/lib/navigation";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("auth");
  return { title: t("loginTitle"), robots: { index: false } };
}

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ next?: string | string[] }>;
}) {
  const { next } = await searchParams;
  const t = await getTranslations("auth");
  return (
    <AuthCard title={t("loginTitle")} intro={t("loginIntro")}>
      <LoginForm next={safeNextPath(typeof next === "string" ? next : undefined)} />
    </AuthCard>
  );
}
