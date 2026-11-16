"use client";
/**
 * Last-resort error boundary for failures in the root layout itself. It replaces the whole
 * document, so it renders its own (English, from the en catalog) brand header and footer.
 */
import { NextIntlClientProvider, useTranslations } from "next-intl";
import { Logo } from "@/components/brand/Logo";
import { PoweredBy } from "@/components/brand/PoweredBy";
import { enMessages } from "@/lib/i18n/messages";
import "./globals.css";

function GlobalErrorContent({ reset }: { reset: () => void }) {
  const t = useTranslations("errorPage");
  return (
    <>
      <header className="border-b border-slate-200 dark:border-navy-800">
        <div className="gh-container py-3">
          <Logo />
        </div>
      </header>
      <main className="gh-container flex flex-1 flex-col items-center py-20 text-center">
        <h1 className="text-3xl font-bold">{t("title")}</h1>
        <p className="gh-muted mt-3 max-w-md">{t("body")}</p>
        <button type="button" onClick={reset} className="gh-btn-primary mt-8">
          {t("retry")}
        </button>
      </main>
      <footer className="border-t border-slate-200 dark:border-navy-800">
        <div className="gh-container py-6">
          <PoweredBy />
        </div>
      </footer>
    </>
  );
}

export default function GlobalError({ reset }: { error: Error; reset: () => void }) {
  return (
    <html lang="en">
      <body className="flex min-h-screen flex-col">
        <NextIntlClientProvider locale="en" messages={enMessages} timeZone="UTC">
          <GlobalErrorContent reset={reset} />
        </NextIntlClientProvider>
      </body>
    </html>
  );
}
