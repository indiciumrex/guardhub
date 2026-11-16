import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import { renderWithIntl } from "@/test/render-with-intl";
import type { ScanDiff, ScanSummary } from "@/lib/types";
import { ScanDiffView } from "./ScanDiffView";
import { CompareScanPicker, earlierDoneScans } from "./CompareScanPicker";

const diff: ScanDiff = {
  scan_id: "scan-3",
  base_scan_id: "scan-2",
  project_id: "p1",
  score: 63,
  base_score: 70,
  score_delta: -7,
  compared_checks: ["exposed_env", "security_headers"],
  skipped_checks: ["tls_cert"],
  new: [
    {
      fingerprint: "fp-new",
      check_id: "exposed_env",
      finding_key: "env_file_exposed",
      severity: "critical",
      title: "Your .env file is public",
      summary: "Anyone can download /.env.",
    },
  ],
  regressed: [
    {
      fingerprint: "fp-back",
      check_id: "security_headers",
      finding_key: "hsts_missing",
      severity: "medium",
      title: "HSTS is missing",
      summary: "Browsers may load the site over plain HTTP.",
    },
  ],
  fixed: [
    {
      fingerprint: "fp-fixed",
      check_id: "security_headers",
      finding_key: "csp_missing",
      severity: "high",
      title: "No CSP header",
      summary: "Scripts from anywhere could run.",
    },
  ],
  unchanged_count: 4,
};

function section(name: RegExp): HTMLElement {
  return screen.getByRole("heading", { name }).closest("section") as HTMLElement;
}

describe("ScanDiffView", () => {
  it("shows score now vs before with the change in words", () => {
    renderWithIntl(<ScanDiffView diff={diff} />);
    expect(screen.getByText("Now")).toBeInTheDocument();
    expect(screen.getByText("Before")).toBeInTheDocument();
    expect(screen.getByText("Down 7 points")).toBeInTheDocument();
  });

  it("lists new, came back and fixed issues with severity text and report links", () => {
    renderWithIntl(<ScanDiffView diff={diff} />);
    const added = section(/New issues/);
    expect(within(added).getByText("Critical")).toBeInTheDocument();
    expect(within(added).getByRole("heading", { name: "Your .env file is public" })).toBeVisible();
    expect(within(added).getByText("Anyone can download /.env.")).toBeInTheDocument();
    expect(within(added).getByRole("link", { name: /View full report/ })).toHaveAttribute(
      "href",
      "/account/scans/scan-3",
    );

    const back = section(/Came back/);
    expect(within(back).getByText("HSTS is missing")).toBeInTheDocument();
    expect(within(back).getByText("Medium")).toBeInTheDocument();

    const fixed = section(/^Fixed/);
    expect(within(fixed).getByText("No CSP header")).toBeInTheDocument();
    expect(within(fixed).getByRole("link", { name: /View earlier report/ })).toHaveAttribute(
      "href",
      "/account/scans/scan-2",
    );
    expect(screen.getByText("4 issues are unchanged.")).toBeInTheDocument();
  });

  it("shows empty states per section", () => {
    renderWithIntl(<ScanDiffView diff={{ ...diff, new: [], regressed: [], fixed: [] }} />);
    expect(screen.getByText("No new issues.")).toBeInTheDocument();
    expect(screen.getByText("Nothing came back.")).toBeInTheDocument();
    expect(screen.getByText("Nothing was fixed since the earlier scan.")).toBeInTheDocument();
  });

  it("names the checks that were skipped because they couldn't run", () => {
    renderWithIntl(<ScanDiffView diff={diff} />);
    const skipped = section(/Not compared/);
    expect(within(skipped).getByText(/couldn't run in one of the two scans/)).toBeInTheDocument();
    expect(within(skipped).getByRole("listitem")).toHaveTextContent("HTTPS and certificate");
  });

  it("shows the baseline state for the first finished scan", () => {
    renderWithIntl(
      <ScanDiffView
        diff={{
          ...diff,
          base_scan_id: null,
          base_score: null,
          score_delta: null,
          new: [],
          regressed: [],
          fixed: [],
          skipped_checks: [],
          unchanged_count: 2,
        }}
      />,
    );
    expect(screen.getByRole("heading", { name: "This is the starting point" })).toBeVisible();
    expect(screen.getByText("This scan found 2 issues.")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /New issues/ })).toBeNull();
    expect(screen.queryByText("Before")).toBeNull();
    expect(screen.queryByText(/Not compared/)).toBeNull();
  });

  it("localises in Turkish", () => {
    renderWithIntl(<ScanDiffView diff={diff} />, "tr");
    expect(screen.getByText("7 puan düştü")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /Geri gelenler/ })).toBeInTheDocument();
    expect(screen.getByText("4 sorun değişmeden duruyor.")).toBeInTheDocument();
  });
});

function scan(id: string, createdAt: string, status: ScanSummary["status"]): ScanSummary {
  return {
    id,
    project_id: "p1",
    target_url: "https://example.com",
    status,
    score: status === "done" ? 70 : null,
    finding_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    created_at: createdAt,
    started_at: null,
    finished_at: null,
    error: null,
    trigger: "manual",
    failed_checks: [],
  };
}

describe("CompareScanPicker", () => {
  const scans = [
    scan("scan-4", "2026-11-16T10:00:00Z", "done"),
    scan("scan-3", "2026-11-15T10:00:00Z", "done"),
    scan("scan-f", "2026-11-14T10:00:00Z", "failed"),
    scan("scan-2", "2026-11-13T10:00:00Z", "done"),
    scan("scan-1", "2026-11-12T10:00:00Z", "done"),
  ];

  it("offers only earlier finished scans", () => {
    expect(earlierDoneScans(scans, "scan-3").map((s) => s.id)).toEqual(["scan-2", "scan-1"]);
    expect(earlierDoneScans(scans, "missing")).toEqual([]);
  });

  it("renders a GET form with the current comparison selected", () => {
    renderWithIntl(
      <CompareScanPicker
        action="/account/projects/p1/compare/scan-3"
        candidates={earlierDoneScans(scans, "scan-3")}
        selectedId="scan-1"
      />,
    );
    const select = screen.getByLabelText("Earlier scan");
    expect(select).toHaveValue("scan-1");
    expect(select).toHaveAttribute("name", "against");
    expect(within(select).getAllByRole("option")).toHaveLength(2);
    expect(select.closest("form")).toHaveAttribute("method", "get");
  });

  it("renders nothing when there is no earlier scan", () => {
    const { container } = renderWithIntl(
      <CompareScanPicker action="/x" candidates={[]} selectedId={null} />,
    );
    expect(container).toBeEmptyDOMElement();
  });
});
