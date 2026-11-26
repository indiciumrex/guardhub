import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithIntl } from "@/test/render-with-intl";
import { CustomerActiveTesting, type ActiveReadiness } from "./CustomerActiveTesting";

const router = { push: vi.fn(), refresh: vi.fn() };
vi.mock("next/navigation", () => ({
  useRouter: () => router,
  usePathname: () => "/account/projects/p1",
}));

let fetchMock: ReturnType<typeof vi.fn>;
beforeEach(() => {
  fetchMock = vi.fn(
    async () =>
      new Response("{}", { status: 202, headers: { "Content-Type": "application/json" } }),
  );
  vi.stubGlobal("fetch", fetchMock);
  router.refresh.mockReset();
});
afterEach(() => vi.unstubAllGlobals());

const base: ActiveReadiness = {
  available: false,
  blocked_by: ["customer_go", "terms_final"],
  terms_version: null,
  checks: ["active_cors", "active_xss"],
  running_scan_id: null,
  ssrf_covered: false,
};

describe("CustomerActiveTesting", () => {
  it("only explains what is missing while it is off: nothing can be started", () => {
    renderWithIntl(<CustomerActiveTesting projectId="p1" readiness={base} />);
    expect(screen.getByText("Not available yet")).toBeInTheDocument();
    const waiting = screen.getByRole("list", { name: "Still waiting for" });
    expect(waiting).toHaveTextContent("GuardHub's go-live decision for customer sites");
    expect(waiting).toHaveTextContent("the published active-testing terms");
    expect(screen.queryByRole("button", { name: "Start the active scan" })).toBeNull();
    expect(screen.getByText(/is not covered in this plan/)).toBeInTheDocument();
  });

  it("does not mention SSRF as missing once the out-of-band service is live", () => {
    renderWithIntl(
      <CustomerActiveTesting
        projectId="p1"
        readiness={{ ...base, ssrf_covered: true, checks: ["active_cors", "active_ssrf"] }}
      />,
    );
    expect(screen.queryByText(/is not covered in this plan/)).toBeNull();
  });

  it("needs the current terms accepted, then starts with them", async () => {
    renderWithIntl(
      <CustomerActiveTesting
        projectId="p1"
        readiness={{ ...base, available: true, blocked_by: [], terms_version: "2026-12-01" }}
      />,
    );
    const start = screen.getByRole("button", { name: "Start the active scan" });
    expect(start).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/accept the active-testing terms, version 2026-12-01/));
    fireEvent.click(start);
    await waitFor(() => expect(router.refresh).toHaveBeenCalled());
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/v1/projects/p1/active/scans");
    expect(JSON.parse(String(init.body))).toEqual({
      checks: ["active_cors", "active_xss"],
      exclude: ["/admin"],
      terms_version: "2026-12-01",
      accept_terms: true,
    });
  });

  it("shows a prominent stop while a scan runs", async () => {
    renderWithIntl(
      <CustomerActiveTesting projectId="p1" readiness={{ ...base, running_scan_id: "s1" }} />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Stop now" }));
    await waitFor(() => expect(router.refresh).toHaveBeenCalled());
    expect((fetchMock.mock.calls[0] as [string])[0]).toBe(
      "/api/v1/projects/p1/active/scans/s1/stop",
    );
  });
});
