/**
 * Inline status message. The tone is shown by an icon and a text prefix, not colour alone.
 */
import type { ReactNode } from "react";

type Tone = "error" | "success" | "info";

const toneClasses: Record<Tone, string> = {
  error:
    "border-red-300 bg-red-50 text-red-900 dark:border-red-800 dark:bg-red-950/60 dark:text-red-100",
  success:
    "border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-100",
  info: "border-sky-300 bg-sky-50 text-sky-900 dark:border-sky-800 dark:bg-sky-950/60 dark:text-sky-100",
};

const icons: Record<Tone, string> = {
  error: "M10 2a8 8 0 1 0 0 16 8 8 0 0 0 0-16Zm-1 4h2v5H9V6Zm0 6h2v2H9v-2Z",
  success:
    "M10 2a8 8 0 1 0 0 16 8 8 0 0 0 0-16Zm-1.2 11.4L5.3 9.9l1.4-1.4 2.1 2.1 4.5-4.5 1.4 1.4-5.9 5.9Z",
  info: "M10 2a8 8 0 1 0 0 16 8 8 0 0 0 0-16Zm-1 4h2v2H9V6Zm0 3h2v5H9V9Z",
};

interface AlertProps {
  tone: Tone;
  /** Short visible prefix, e.g. "Error". */
  label: string;
  children: ReactNode;
  className?: string;
}

export function Alert({ tone, label, children, className = "" }: AlertProps) {
  return (
    <div
      role={tone === "error" ? "alert" : "status"}
      className={`flex gap-3 rounded-lg border px-4 py-3 text-sm ${toneClasses[tone]} ${className}`}
    >
      <svg
        viewBox="0 0 20 20"
        className="mt-0.5 h-5 w-5 shrink-0"
        aria-hidden="true"
        focusable="false"
      >
        <path fill="currentColor" d={icons[tone]} />
      </svg>
      <div>
        <strong className="font-semibold">{label}: </strong>
        {children}
      </div>
    </div>
  );
}
