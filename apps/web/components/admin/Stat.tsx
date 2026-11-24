/**
 * Small presentational pieces shared by the admin control centre pages (server-safe).
 */
import type { ReactNode } from "react";

export function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: string }) {
  return (
    <div className="gh-card p-4">
      <dt className="gh-muted text-xs font-semibold uppercase tracking-wide">{label}</dt>
      <dd className="mt-1 text-2xl font-bold tabular-nums">{value}</dd>
      {hint ? <dd className="gh-muted mt-1 text-xs">{hint}</dd> : null}
    </div>
  );
}

const tones = {
  good: "border-emerald-300 text-emerald-800 dark:border-emerald-700 dark:text-emerald-200",
  warn: "border-amber-300 text-amber-900 dark:border-amber-700 dark:text-amber-200",
  bad: "border-red-300 text-red-800 dark:border-red-700 dark:text-red-200",
  neutral: "border-slate-300 text-slate-700 dark:border-slate-600 dark:text-slate-200",
} as const;

/** A text badge; the tone is a secondary cue, the text carries the meaning. */
export function Badge({ tone, children }: { tone: keyof typeof tones; children: ReactNode }) {
  return (
    <span
      className={`inline-flex rounded-full border px-2.5 py-0.5 text-xs font-semibold ${tones[tone]}`}
    >
      {children}
    </span>
  );
}

export function Section({
  id,
  title,
  intro,
  children,
}: {
  id: string;
  title: string;
  intro?: string;
  children: ReactNode;
}) {
  return (
    <section aria-labelledby={id} className="space-y-3">
      <h2 id={id} className="text-xl font-semibold">
        {title}
      </h2>
      {intro ? <p className="gh-muted max-w-3xl text-sm">{intro}</p> : null}
      {children}
    </section>
  );
}

export function pct(value: number | null | undefined): string {
  if (value === null || value === undefined) return "-";
  return `${(value * 100).toFixed(value === 1 || value === 0 ? 0 : 1)}%`;
}
