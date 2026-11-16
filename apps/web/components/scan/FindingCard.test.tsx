import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import { renderWithIntl } from "@/test/render-with-intl";
import type { FindingView } from "@/lib/types";
import { FindingCard } from "./FindingCard";
import { splitFixSteps } from "./FixSteps";

const finding: FindingView = {
  id: "f1",
  check_id: "exposed_env",
  finding_key: "env_file_exposed",
  severity: "critical",
  title: "Your .env file is public",
  summary: "Anyone can download /.env, which holds 3 secrets.",
  why: "Attackers use these keys to reach your database.",
  fix: "1. Delete the file from your web root.\n2. Rotate every key in it.\n3. Block `.env` in your server config.",
  evidence: {
    kind: "http_response",
    location: "https://example.com/.env",
    redacted_payload: "DB_PASSWORD=****abcd",
  },
  status: "open",
};

describe("FindingCard", () => {
  it("renders title, what/why/fix sections and fix steps", () => {
    renderWithIntl(<FindingCard finding={finding} />);
    const card = screen.getByRole("article", { name: finding.title });
    expect(within(card).getByRole("heading", { name: finding.title })).toBeInTheDocument();
    expect(within(card).getByText("What's exposed")).toBeInTheDocument();
    expect(within(card).getByText(finding.summary)).toBeInTheDocument();
    expect(within(card).getByText("Why it matters")).toBeInTheDocument();
    expect(within(card).getByText(finding.why)).toBeInTheDocument();
    expect(within(card).getByText("How to fix it")).toBeInTheDocument();

    const steps = within(card).getAllByRole("listitem");
    expect(steps).toHaveLength(3);
    expect(steps[0]).toHaveTextContent("Delete the file from your web root.");
    expect(within(card).getByText(".env", { selector: "code" })).toBeInTheDocument();
  });

  it("shows the severity as text, not only colour", () => {
    renderWithIntl(<FindingCard finding={finding} />);
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });

  it("puts masked evidence in a collapsible block, as text", () => {
    renderWithIntl(
      <FindingCard
        finding={{
          ...finding,
          evidence: { ...finding.evidence, redacted_payload: "<script>x</script>" },
        }}
      />,
    );
    const details = screen.getByText("Show evidence (masked)").closest("details");
    expect(details).not.toBeNull();
    expect(details).not.toHaveAttribute("open");
    expect(within(details as HTMLElement).getByText("<script>x</script>")).toBeInTheDocument();
    expect(document.querySelector("details script")).toBeNull();
  });

  it("localises labels in Turkish", () => {
    renderWithIntl(<FindingCard finding={finding} />, "tr");
    expect(screen.getByText("Ne açıkta?")).toBeInTheDocument();
    expect(screen.getByText("Kritik")).toBeInTheDocument();
  });
});

describe("splitFixSteps", () => {
  it("splits numbered lines and inline numbering", () => {
    expect(splitFixSteps("- a\n- b")).toEqual(["a", "b"]);
    expect(splitFixSteps("1. Do this. 2. Then that.")).toEqual(["Do this.", "Then that."]);
  });

  it("keeps a single paragraph intact", () => {
    expect(splitFixSteps("Upgrade to TLS 1.2 or later.")).toEqual(["Upgrade to TLS 1.2 or later."]);
  });
});
