/**
 * Renders fix guidance as readable steps. The API sends plain text; lines (or "1." / "-"
 * prefixes) become list items and `backticks` become inline code. Text only, never HTML.
 */
import type { ReactNode } from "react";

const BULLET = /^\s*(?:\d+[.)]|[-*•])\s+/;

export function splitFixSteps(fix: string): string[] {
  const lines = fix
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  if (lines.length > 1) return lines.map((line) => line.replace(BULLET, ""));
  // One paragraph with inline numbering: "1. Do this. 2. Then that."
  const inline = fix.split(/\s+(?=\d+[.)]\s)/).map((part) => part.trim());
  if (/^\s*1[.)]\s/.test(fix) && inline.length > 1)
    return inline.map((part) => part.replace(BULLET, "")).filter(Boolean);
  return lines.map((line) => line.replace(BULLET, ""));
}

function withInlineCode(text: string): ReactNode[] {
  return text.split(/(`[^`]+`)/g).map((part, index) =>
    part.startsWith("`") && part.endsWith("`") && part.length > 2 ? (
      <code
        key={index}
        className="rounded bg-slate-100 px-1 py-0.5 font-mono text-[0.9em] text-navy-900 dark:bg-navy-800 dark:text-slate-100"
      >
        {part.slice(1, -1)}
      </code>
    ) : (
      part
    ),
  );
}

export function FixSteps({ fix }: { fix: string }) {
  const steps = splitFixSteps(fix);
  if (steps.length <= 1) return <p>{withInlineCode(steps[0] ?? fix)}</p>;
  return (
    <ol className="list-decimal space-y-1.5 pl-5 marker:font-semibold">
      {steps.map((step, index) => (
        <li key={index}>{withInlineCode(step)}</li>
      ))}
    </ol>
  );
}
