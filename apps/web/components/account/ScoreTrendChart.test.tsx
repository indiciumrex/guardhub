import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import { renderWithIntl } from "@/test/render-with-intl";
import type { TrendPoint } from "@/lib/types";
import { ScoreTrendChart } from "./ScoreTrendChart";

const points: TrendPoint[] = [
  { scan_id: "s1", finished_at: "2026-11-01T09:00:00Z", score: 55, trigger: "manual" },
  { scan_id: "s2", finished_at: "2026-11-08T09:00:00Z", score: 40, trigger: "scheduled" },
  { scan_id: "s3", finished_at: "2026-11-15T09:00:00Z", score: 86, trigger: "scheduled" },
];

describe("ScoreTrendChart", () => {
  it("shows a plain message and no chart when there are no finished scans", () => {
    renderWithIntl(<ScoreTrendChart points={[]} />);
    expect(screen.getByText(/No finished scans yet/)).toBeInTheDocument();
    expect(screen.queryByRole("img")).toBeNull();
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("handles a single point: one marker, no line, a hint and a one-row table", () => {
    renderWithIntl(<ScoreTrendChart points={[points[0]!]} />);
    const chart = screen.getByRole("img", { name: /Security score over time/ });
    expect(chart).toHaveAccessibleName(expect.stringContaining("score of 55 out of 100"));
    expect(chart.querySelectorAll("circle[r='5']")).toHaveLength(1);
    expect(chart.querySelector("path[fill='none']")).toBeNull();
    expect(screen.getByText(/Run another scan to start a trend/)).toBeInTheDocument();
    const table = screen.getByRole("table", { name: /Score after each finished scan/ });
    expect(within(table).getAllByRole("row")).toHaveLength(2);
  });

  it("draws many points with a text summary and the same data in a hidden table", () => {
    renderWithIntl(<ScoreTrendChart points={points} />);
    const chart = screen.getByRole("img", { name: /Security score over time/ });
    expect(chart).toHaveAccessibleName(
      expect.stringContaining("The score went from 55 to 86 out of 100. Lowest 40, highest 86."),
    );
    expect(chart.querySelector("path[fill='none']")).not.toBeNull();
    // manual = circle, automatic = diamond, so the trigger is not shown by colour alone
    expect(chart.querySelectorAll("circle[r='5']")).toHaveLength(1);
    expect(screen.getByText("Latest: 86")).toBeInTheDocument();

    const table = screen.getByRole("table", { name: /Score after each finished scan/ });
    expect(table).toHaveClass("sr-only");
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(4);
    expect(rows[1]).toHaveTextContent("55");
    expect(rows[1]).toHaveTextContent("Manual");
    expect(rows[3]).toHaveTextContent("86");
    expect(rows[3]).toHaveTextContent("Scheduled");
  });

  it("localises the summary in Turkish", () => {
    renderWithIntl(<ScoreTrendChart points={points} />, "tr");
    expect(screen.getByRole("img", { name: /Zaman içinde güvenlik puanı/ })).toBeInTheDocument();
    expect(screen.getByRole("table", { name: /en eskisi en üstte/ })).toHaveTextContent(
      "Zamanlanmış",
    );
  });
});
