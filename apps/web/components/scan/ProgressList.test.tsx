import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import { renderWithIntl } from "@/test/render-with-intl";
import type { ProgressItem } from "@/lib/types";
import { ProgressList } from "./ProgressList";

const items: ProgressItem[] = [
  { check_id: "exposed_env", name: "Leaked secrets", status: "done" },
  { check_id: "security_headers", name: "Security headers", status: "running" },
  { check_id: "tls_cert", name: "", status: "queued" },
  { check_id: "open_admin", name: "Admin pages", status: "failed" },
];

describe("ProgressList", () => {
  it("renders one row per check with a text status", () => {
    renderWithIntl(<ProgressList items={items} />);
    const rows = screen.getAllByRole("listitem");
    expect(rows).toHaveLength(4);
    expect(rows[0]).toHaveTextContent("Leaked secrets");
    expect(rows[0]).toHaveTextContent("Done");
    expect(rows[1]).toHaveTextContent("Checking…");
    expect(rows[2]).toHaveTextContent("Waiting");
    expect(rows[3]).toHaveTextContent("Couldn't finish");
  });

  it("shows a safe stop as incomplete, not as a failure", () => {
    renderWithIntl(
      <ProgressList
        items={[
          {
            check_id: "exposed_files",
            name: "Forgotten files",
            status: "failed",
            reason: "budget_exceeded",
          },
          { check_id: "dns_email", name: "E-mail", status: "failed", reason: "target_unreachable" },
        ]}
      />,
    );
    const rows = screen.getAllByRole("listitem");
    expect(rows[0]).toHaveTextContent("Incomplete (safe stop)");
    expect(rows[0]).not.toHaveTextContent("Couldn't finish");
    expect(rows[1]).toHaveTextContent("Couldn't finish");
  });

  it("falls back to the catalog name when the API sends none", () => {
    renderWithIntl(<ProgressList items={items} />);
    expect(screen.getByText("HTTPS and certificate")).toBeInTheDocument();
  });

  it("announces overall progress in a polite live region", () => {
    renderWithIntl(<ProgressList items={items} />);
    const live = screen.getByText(/2 of 4 checks finished/);
    expect(live).toHaveAttribute("aria-live", "polite");
    expect(live).toHaveTextContent("Now checking: Security headers.");
  });

  it("shows a waiting message when there is no progress yet", () => {
    renderWithIntl(<ProgressList items={[]} />);
    expect(screen.getByText(/in the queue/)).toBeInTheDocument();
  });
});
