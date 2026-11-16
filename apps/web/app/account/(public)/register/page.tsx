import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { AuthCard } from "@/components/account/AuthCard";
import { RegisterForm } from "@/components/account/RegisterForm";
import { safeNextPath } from "@/lib/navigation";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("auth");
  return { title: t("registerTitle"), robots: { index: false } };
}

export default async function RegisterPage({
  searchParams,
}: {
  searchParams: Promise<{ next?: string | string[] }>;
}) {
  const { next } = await searchParams;
  const t = await getTranslations("auth");
  return (
    <AuthCard title={t("registerTitle")} intro={t("registerIntro")}>
      <RegisterForm next={safeNextPath(typeof next === "string" ? next : undefined)} />
    </AuthCard>
  );
}
