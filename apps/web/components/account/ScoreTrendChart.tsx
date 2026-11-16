/**
 * Score trend (docs/architecture.md §8.3): a hand-made SVG line of the score after each
 * finished scan, oldest on the left. Accessible by construction: the SVG has a title and a
 * text description, every point has its own tooltip title, and a visually hidden table holds
 * the same data. Points are evenly spaced (one per scan); the table carries the exact dates.
 * Manual and automatic scans use different marker shapes, so the trigger is never colour-only.
 */
import { useFormatter, useTranslations } from "next-intl";
import type { ScanTrigger, TrendPoint } from "@/lib/types";

const WIDTH = 640;
const HEIGHT = 240;
const PAD = { top: 16, right: 88, bottom: 32, left: 40 };
const PLOT_W = WIDTH - PAD.left - PAD.right;
const PLOT_H = HEIGHT - PAD.top - PAD.bottom;
const GRID = [0, 50, 100];

function xFor(index: number, count: number): number {
  if (count <= 1) return PAD.left + PLOT_W / 2;
  return PAD.left + (index / (count - 1)) * PLOT_W;
}

function yFor(score: number): number {
  const clamped = Math.max(0, Math.min(100, score));
  return PAD.top + PLOT_H - (clamped / 100) * PLOT_H;
}

function Marker({ trigger, x, y }: { trigger: ScanTrigger; x: number; y: number }) {
  const common =
    "fill-teal-700 stroke-white stroke-2 dark:fill-teal-300 dark:stroke-navy-900" as const;
  if (trigger === "manual") return <circle cx={x} cy={y} r={5} className={common} />;
  // Automatic (scheduled / CI) scans: a diamond.
  return (
    <path d={`M${x} ${y - 6} L${x + 6} ${y} L${x} ${y + 6} L${x - 6} ${y} Z`} className={common} />
  );
}

export function ScoreTrendChart({ points }: { points: TrendPoint[] }) {
  const t = useTranslations("trend");
  const format = useFormatter();
  const formatDate = (value: string) =>
    format.dateTime(new Date(value), { dateStyle: "medium", timeZone: "UTC" });
  const formatDateTime = (value: string) =>
    format.dateTime(new Date(value), { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" });

  const first = points[0];
  const last = points[points.length - 1];
  if (!first || !last) {
    return <p className="gh-muted">{t("empty")}</p>;
  }

  const scores = points.map((point) => point.score);
  const description =
    points.length === 1
      ? t("summarySingle", { date: formatDate(first.finished_at), score: first.score })
      : t("summary", {
          count: points.length,
          firstDate: formatDate(first.finished_at),
          lastDate: formatDate(last.finished_at),
          first: first.score,
          last: last.score,
          min: Math.min(...scores),
          max: Math.max(...scores),
        });
  const coords = points.map((point, index) => ({
    point,
    x: xFor(index, points.length),
    y: yFor(point.score),
  }));
  const linePath = coords
    .map(({ x, y }, index) => `${index === 0 ? "M" : "L"}${x.toFixed(1)} ${y.toFixed(1)}`)
    .join(" ");
  const lastCoord = { x: xFor(points.length - 1, points.length), y: yFor(last.score) };
  const hasManual = points.some((point) => point.trigger === "manual");
  const hasAutomatic = points.some((point) => point.trigger !== "manual");

  return (
    <figure className="space-y-3">
      {points.length === 1 ? (
        <p className="gh-muted text-sm">{t("single", { score: first.score })}</p>
      ) : null}
      <svg
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        className="h-auto w-full max-w-3xl"
        role="img"
        aria-labelledby="trend-chart-title trend-chart-desc"
      >
        <title id="trend-chart-title">{t("chartTitle")}</title>
        <desc id="trend-chart-desc">{description}</desc>
        {GRID.map((value) => (
          <g key={value}>
            <line
              x1={PAD.left}
              x2={PAD.left + PLOT_W}
              y1={yFor(value)}
              y2={yFor(value)}
              className="stroke-slate-200 dark:stroke-navy-700"
              strokeWidth={1}
            />
            <text
              x={PAD.left - 8}
              y={yFor(value)}
              textAnchor="end"
              dominantBaseline="middle"
              className="fill-slate-600 text-[12px] dark:fill-slate-300"
            >
              {value}
            </text>
          </g>
        ))}
        <text
          x={points.length === 1 ? xFor(0, 1) : PAD.left}
          y={HEIGHT - 8}
          textAnchor={points.length === 1 ? "middle" : "start"}
          className="fill-slate-600 text-[12px] dark:fill-slate-300"
        >
          {formatDate(first.finished_at)}
        </text>
        {points.length > 1 ? (
          <text
            x={PAD.left + PLOT_W}
            y={HEIGHT - 8}
            textAnchor="end"
            className="fill-slate-600 text-[12px] dark:fill-slate-300"
          >
            {formatDate(last.finished_at)}
          </text>
        ) : null}
        {points.length > 1 ? (
          <path
            d={linePath}
            fill="none"
            strokeWidth={2}
            strokeLinejoin="round"
            strokeLinecap="round"
            className="stroke-teal-700 dark:stroke-teal-300"
          />
        ) : null}
        {coords.map(({ point, x, y }) => (
          <g key={point.scan_id}>
            <title>
              {t("pointLabel", {
                date: formatDateTime(point.finished_at),
                score: point.score,
                trigger: t(`trigger.${point.trigger}`),
              })}
            </title>
            {/* Larger invisible hit target for the tooltip. */}
            <circle cx={x} cy={y} r={12} fill="transparent" />
            <Marker trigger={point.trigger} x={x} y={y} />
          </g>
        ))}
        <text
          x={lastCoord.x + 10}
          y={lastCoord.y}
          dominantBaseline="middle"
          className="fill-navy-950 text-[12px] font-semibold dark:fill-slate-100"
        >
          {t("latest", { score: last.score })}
        </text>
      </svg>
      {/* Visual legend only; the hidden table below names the trigger of every point. */}
      <div className="gh-muted flex flex-wrap gap-4 text-xs" aria-hidden="true">
        {hasManual ? (
          <span className="inline-flex items-center gap-1.5">
            <svg viewBox="0 0 12 12" className="h-3 w-3" focusable="false">
              <circle cx="6" cy="6" r="5" className="fill-teal-700 dark:fill-teal-300" />
            </svg>
            {t("legendManual")}
          </span>
        ) : null}
        {hasAutomatic ? (
          <span className="inline-flex items-center gap-1.5">
            <svg viewBox="0 0 12 12" className="h-3 w-3" focusable="false">
              <path d="M6 0 L12 6 L6 12 L0 6 Z" className="fill-teal-700 dark:fill-teal-300" />
            </svg>
            {t("legendScheduled")}
          </span>
        ) : null}
      </div>
      <table className="sr-only">
        <caption>{t("tableCaption")}</caption>
        <thead>
          <tr>
            <th scope="col">{t("colDate")}</th>
            <th scope="col">{t("colScore")}</th>
            <th scope="col">{t("colTrigger")}</th>
          </tr>
        </thead>
        <tbody>
          {points.map((point) => (
            <tr key={point.scan_id}>
              <td>{formatDateTime(point.finished_at)}</td>
              <td>{point.score}</td>
              <td>{t(`trigger.${point.trigger}`)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </figure>
  );
}
