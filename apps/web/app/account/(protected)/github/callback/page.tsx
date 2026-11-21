/**
 * GitHub App "Callback URL" (ADR-0006 §3; ops/runbooks/production.md §9): finishes connecting
 * GitHub for the signed-in user.
 */
import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { GitHubCallback } from "@/components/account/GitHubCallback";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("github");
  return { title: t("callbackTitle") };
}

function one(value: string | string[] | undefined): string | null {
  return typeof value === "string" && value.length > 0 && value.length <= 200 ? value : null;
}

export default async function GitHubCallbackPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  return (
    <GitHubCallback
      code={one(params.code)}
      installationId={one(params.installation_id)}
      state={one(params.state)}
      setupAction={one(params.setup_action)}
    />
  );
}
