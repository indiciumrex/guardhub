/**
 * The admin console's design system (server-safe): page header, panels, status badges, key-value
 * rows, shortened technical ids and stats. Status colour always comes with an icon and words
 * (WCAG 1.4.1); tones mean something (ok / warn / crit / info / neutral / locked), never decoration.
 */
import type { ReactNode } from "react";

export type Tone = "ok" | "warn" | "crit" | "info" | "neutral" | "locked";

const toneClass: Record<Tone, string> = {
  ok: "gh-tone-ok",
  warn: "gh-tone-warn",
  crit: "gh-tone-crit",
  info: "gh-tone-info",
  neutral: "gh-tone-neutral",
  locked: "gh-tone-locked",
};

// One shape per tone: check, triangle, octagon-x, "i", dot, padlock.
const toneIcon: Record<Tone, string> = {
  ok: "M10 2a8 8 0 1 0 0 16 8 8 0 0 0 0-16Zm3.7 5.3 1.4 1.4L9 14.8 5.3 11.1l1.4-1.4L9 12l4.7-4.7Z",
  warn: "M10 2 19 18H1L10 2Zm-1 6v4h2V8H9Zm0 5v2h2v-2H9Z",
  crit: "M7 2h6l5 5v6l-5 5H7l-5-5V7l5-5Zm.5 4.1L6.1 7.5 8.6 10l-2.5 2.5 1.4 1.4 2.5-2.5 2.5 2.5 1.4-1.4-2.5-2.5 2.5-2.5-1.4-1.4L10 8.6 7.5 6.1Z",
  info: "M10 2a8 8 0 1 0 0 16 8 8 0 0 0 0-16Zm-1 3.5h2v2H9v-2Zm0 3.5h2v6H9V9Z",
  neutral: "M10 6a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z",
  locked:
    "M6 8V6a4 4 0 1 1 8 0v2h1a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V9a1 1 0 0 1 1-1h1Zm2 0h4V6a2 2 0 1 0-4 0v2Zm1 4v3h2v-3H9Z",
};

export function ToneIcon({ tone, className = "h-3.5 w-3.5" }: { tone: Tone; className?: string }) {
  return (
    <svg
      viewBox="0 0 20 20"
      className={`shrink-0 ${className}`}
      aria-hidden="true"
      focusable="false"
    >
      <path fill="currentColor" fillRule="evenodd" d={toneIcon[tone]} />
    </svg>
  );
}

/** A status badge: icon + words; the tone is a secondary cue. */
export function StatusBadge({
  tone,
  children,
  size = "sm",
}: {
  tone: Tone;
  children: ReactNode;
  size?: "sm" | "lg";
}) {
  const s = size === "lg" ? "gap-2 px-3 py-1 text-sm" : "gap-1.5 px-2.5 py-0.5 text-xs";
  return (
    <span
      className={`inline-flex items-center rounded-full border font-semibold ${s} ${toneClass[tone]}`}
    >
      <ToneIcon tone={tone} className={size === "lg" ? "h-4 w-4" : "h-3.5 w-3.5"} />
      <span>{children}</span>
    </span>
  );
}

/** Kept for existing call sites: good → ok, bad → crit. */
export function Badge({
  tone,
  children,
}: {
  tone: "good" | "warn" | "bad" | "neutral";
  children: ReactNode;
}) {
  const map = { good: "ok", warn: "warn", bad: "crit", neutral: "neutral" } as const;
  return <StatusBadge tone={map[tone]}>{children}</StatusBadge>;
}

export function PageHeader({
  eyebrow,
  title,
  intro,
  actions,
}: {
  eyebrow?: string;
  title: ReactNode;
  intro?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        {eyebrow ? <p className="gh-eyebrow">{eyebrow}</p> : null}
        <h1 className="mt-1 text-2xl font-bold tracking-tight sm:text-3xl">{title}</h1>
        {intro ? <p className="gh-muted mt-2 max-w-3xl text-sm">{intro}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap gap-2">{actions}</div> : null}
    </header>
  );
}

/** A card with a titled header. `emphasis` draws a coloured edge for safety-critical panels. */
export function Panel({
  id,
  title,
  intro,
  actions,
  emphasis,
  children,
  bodyClassName = "gh-panel-body",
}: {
  id?: string;
  title?: ReactNode;
  intro?: string;
  actions?: ReactNode;
  emphasis?: Tone;
  children: ReactNode;
  bodyClassName?: string;
}) {
  const edge = emphasis
    ? {
        ok: "border-l-4 border-l-emerald-600",
        warn: "border-l-4 border-l-amber-500",
        crit: "border-l-4 border-l-red-600",
        info: "border-l-4 border-l-sky-600",
        neutral: "border-l-4 border-l-slate-400",
        locked: "border-l-4 border-l-navy-700 dark:border-l-navy-300",
      }[emphasis]
    : "";
  return (
    <section aria-labelledby={title && id ? id : undefined} className={`gh-panel ${edge}`}>
      {title ? (
        <div className="gh-panel-head">
          <div className="min-w-0">
            <h3 id={id} className="text-base font-semibold">
              {title}
            </h3>
            {intro ? <p className="gh-muted mt-0.5 text-xs">{intro}</p> : null}
          </div>
          {actions}
        </div>
      ) : null}
      <div className={bodyClassName}>{children}</div>
    </section>
  );
}

/** Key-value rows: label left, value right. */
export function KV({ rows }: { rows: { label: ReactNode; value: ReactNode; key?: string }[] }) {
  return (
    <dl className="text-sm">
      {rows.map((r, i) => (
        <div key={r.key ?? i} className="gh-kv">
          <dt className="gh-muted">{r.label}</dt>
          <dd className="text-right font-medium">{r.value}</dd>
        </div>
      ))}
    </dl>
  );
}

/**
 * A technical id (hash, UUID, revision) in monospace, shortened in lists. The full value is the
 * accessible name and the tooltip on hover and keyboard focus.
 */
export function HashId({ value, chars = 8 }: { value: string | null | undefined; chars?: number }) {
  if (!value) return <span className="gh-muted">-</span>;
  if (value.length <= chars + 1) return <span className="font-mono text-xs">{value}</span>;
  return (
    <span
      className="gh-tip font-mono text-xs"
      data-tip={value}
      tabIndex={0}
      aria-label={value}
      title={value}
    >
      {value.slice(0, chars)}…
    </span>
  );
}

export function Stat({
  label,
  value,
  hint,
  tone,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: Tone;
}) {
  return (
    <div className="gh-panel px-4 py-3">
      <dt className="gh-eyebrow flex items-center gap-1.5">
        {tone ? <ToneIcon tone={tone} /> : null}
        {label}
      </dt>
      <dd className="mt-1 text-2xl font-semibold tabular-nums">{value}</dd>
      {hint ? <dd className="gh-muted mt-0.5 text-xs">{hint}</dd> : null}
    </div>
  );
}

export function Section({
  id,
  title,
  intro,
  actions,
  children,
}: {
  id: string;
  title: string;
  intro?: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section aria-labelledby={id} className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 id={id} className="text-lg font-semibold tracking-tight">
            {title}
          </h2>
          {intro ? <p className="gh-muted mt-1 max-w-3xl text-sm">{intro}</p> : null}
        </div>
        {actions}
      </div>
      {children}
    </section>
  );
}

export function pct(value: number | null | undefined): string {
  if (value === null || value === undefined) return "-";
  return `${(value * 100).toFixed(value === 1 || value === 0 ? 0 : 1)}%`;
}
