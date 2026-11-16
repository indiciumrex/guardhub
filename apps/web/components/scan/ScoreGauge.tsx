/**
 * Score ring (0–100) with the number and a text rating, so it reads without colour.
 */
import { useTranslations } from "next-intl";

export type ScoreRating = "good" | "fair" | "poor";

export function scoreRating(score: number): ScoreRating {
  if (score >= 80) return "good";
  if (score >= 50) return "fair";
  return "poor";
}

const ringClass: Record<ScoreRating, string> = {
  good: "stroke-emerald-600 dark:stroke-emerald-400",
  fair: "stroke-amber-500 dark:stroke-amber-400",
  poor: "stroke-red-600 dark:stroke-red-400",
};

const RADIUS = 52;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

export function ScoreGauge({ score }: { score: number }) {
  const t = useTranslations("report");
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  const rating = scoreRating(clamped);
  const dash = (clamped / 100) * CIRCUMFERENCE;
  return (
    <figure className="flex flex-col items-center">
      <div className="relative h-36 w-36">
        <svg
          viewBox="0 0 120 120"
          className="h-full w-full -rotate-90"
          aria-hidden="true"
          focusable="false"
        >
          <circle
            cx="60"
            cy="60"
            r={RADIUS}
            fill="none"
            strokeWidth="10"
            className="stroke-slate-200 dark:stroke-navy-800"
          />
          <circle
            cx="60"
            cy="60"
            r={RADIUS}
            fill="none"
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={`${dash} ${CIRCUMFERENCE}`}
            className={ringClass[rating]}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-4xl font-bold tabular-nums">{clamped}</span>
          <span className="gh-muted text-xs">{t("outOf")}</span>
        </div>
      </div>
      <figcaption className="mt-2 text-center">
        <span className="sr-only">{t("scoreLabel", { score: clamped })} </span>
        <span className="font-semibold">{t(`rating.${rating}`)}</span>
      </figcaption>
    </figure>
  );
}
