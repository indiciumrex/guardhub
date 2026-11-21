"use client";
/**
 * Completes a GitHub App installation (ADR-0006 §3): GitHub redirects here with `code`,
 * `installation_id` and our `state`; the API proves the installation belongs to this GitHub user
 * before binding it. Runs once per page load.
 */
import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import { useErrorMessage } from "@/lib/use-error-message";
import { Alert } from "@/components/ui/Alert";

interface Props {
  code: string | null;
  installationId: string | null;
  state: string | null;
  setupAction: string | null;
}

export function GitHubCallback({ code, installationId, state, setupAction }: Props) {
  const t = useTranslations("github");
  const tCommon = useTranslations("common");
  const router = useRouter();
  const errorMessage = useErrorMessage();
  const started = useRef(false);
  const pending = setupAction === "request";
  const complete =
    !pending && Boolean(code && installationId && state && /^\d+$/.test(installationId));
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    if (!complete || started.current) return;
    started.current = true;
    apiFetch("/github/installations", {
      method: "POST",
      body: { code, installation_id: Number(installationId), state },
    })
      .then(() => router.replace("/account#github"))
      .catch((err: unknown) => setError(err));
  }, [complete, code, installationId, state, router]);

  let body;
  if (pending) {
    body = (
      <Alert tone="info" label={t("pendingLabel")}>
        {t("callbackPending")}
      </Alert>
    );
  } else if (!complete) {
    body = (
      <Alert tone="error" label={tCommon("errorLabel")}>
        {t("callbackMissing")}
      </Alert>
    );
  } else if (error) {
    body = (
      <Alert tone="error" label={tCommon("errorLabel")}>
        {errorMessage(error)}
      </Alert>
    );
  } else {
    body = <p className="gh-muted">{t("callbackWorking")}</p>;
  }

  return (
    <div className="max-w-2xl space-y-4">
      <h1 className="text-2xl font-bold">{t("callbackTitle")}</h1>
      {body}
      <Link href="/account#github" className="gh-link text-sm">
        {t("backToAccount")}
      </Link>
    </div>
  );
}
