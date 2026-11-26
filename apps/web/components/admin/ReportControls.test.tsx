import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithIntl } from "@/test/render-with-intl";
import { PrintReport, ReportScheduleSwitch } from "./ReportControls";

const router = { push: vi.fn(), refresh: vi.fn() };
vi.mock("next/navigation", () => ({
  useRouter: () => router,
  usePathname: () => "/admin/reports",
}));

let fetchMock: ReturnType<typeof vi.fn>;
beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
  router.refresh.mockReset();
});
afterEach(() => vi.unstubAllGlobals());

describe("ReportScheduleSwitch", () => {
  it("switches the weekly summary on", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ frequency: "weekly", enabled: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    renderWithIntl(
      <ReportScheduleSwitch
        schedule={{
          frequency: "weekly",
          enabled: false,
          last_sent_at: null,
          updated_at: "2026-11-26T00:00:00Z",
        }}
        label="Weekly summary"
      />,
    );
    fireEvent.click(screen.getByRole("switch", { name: "Weekly summary" }));
    await waitFor(() => expect(router.refresh).toHaveBeenCalled());
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/v1/admin/report-schedules/weekly");
    expect(init.method).toBe("PUT");
    expect(JSON.parse(String(init.body))).toEqual({ enabled: true });
  });
});

describe("PrintReport", () => {
  it("opens the print dialog (save as PDF)", () => {
    const print = vi.fn();
    vi.stubGlobal("print", print);
    renderWithIntl(<PrintReport />);
    fireEvent.click(screen.getByRole("button", { name: "Print / save as PDF" }));
    expect(print).toHaveBeenCalled();
  });
});
