import Link from "next/link";
import { useTranslations } from "next-intl";
import { ShieldMark } from "@/components/brand/ShieldMark";

export default function NotFound() {
  const t = useTranslations("notFound");
  return (
    <section className="gh-container flex flex-col items-center py-20 text-center">
      <ShieldMark className="h-16 w-16" />
      <p className="mt-6 text-sm font-semibold uppercase tracking-wide text-teal-800 dark:text-teal-300">
        {t("code")}
      </p>
      <h1 className="mt-2 text-3xl font-bold">{t("title")}</h1>
      <p className="gh-muted mt-3 max-w-md">{t("body")}</p>
      <div className="mt-8 flex flex-wrap justify-center gap-3">
        <Link href="/" className="gh-btn-primary">
          {t("home")}
        </Link>
        <Link href="/scan" className="gh-btn-secondary">
          {t("scan")}
        </Link>
      </div>
    </section>
  );
}
