"use client";
/**
 * Route-level error boundary. Rendered inside the root layout, so the branded header and
 * footer stay visible. Never shows raw error details to the user.
 */
import Link from "next/link";
import { useTranslations } from "next-intl";
import { ShieldMark } from "@/components/brand/ShieldMark";

export default function ErrorPage({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  const t = useTranslations("errorPage");
  return (
    <section className="gh-container flex flex-col items-center py-20 text-center">
      <ShieldMark className="h-16 w-16" />
      <h1 className="mt-6 text-3xl font-bold">{t("title")}</h1>
      <p className="gh-muted mt-3 max-w-md">{t("body")}</p>
      {error.digest ? (
        <p className="gh-muted mt-2 text-xs">{t("reference", { digest: error.digest })}</p>
      ) : null}
      <div className="mt-8 flex flex-wrap justify-center gap-3">
        <button type="button" onClick={reset} className="gh-btn-primary">
          {t("retry")}
        </button>
        <Link href="/" className="gh-btn-secondary">
          {t("home")}
        </Link>
      </div>
    </section>
  );
}
