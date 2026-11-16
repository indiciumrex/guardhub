"use client";
/**
 * A read-only value with a "Copy" button. The copied confirmation is announced politely.
 */
import { useId, useState } from "react";
import { useTranslations } from "next-intl";

export function CopyField({ label, value }: { label: string; value: string }) {
  const t = useTranslations("common");
  const id = useId();
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2500);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div>
      <label htmlFor={id} className="gh-label">
        {label}
      </label>
      <div className="flex gap-2">
        <input
          id={id}
          readOnly
          value={value}
          spellCheck={false}
          onFocus={(event) => event.currentTarget.select()}
          className="gh-input font-mono text-sm"
        />
        <button type="button" onClick={copy} className="gh-btn-secondary shrink-0">
          {copied ? t("copied") : t("copy")}
          <span className="sr-only"> {label}</span>
        </button>
      </div>
      <p aria-live="polite" className="sr-only">
        {copied ? t("copiedAnnouncement", { label }) : ""}
      </p>
    </div>
  );
}
