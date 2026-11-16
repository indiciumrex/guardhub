import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithIntl } from "@/test/render-with-intl";
import { ScheduleControl, type ScheduleState } from "./ScheduleControl";

const refresh = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh, push: vi.fn() }),
}));

const off: ScheduleState = {
  scan_frequency: "off",
  next_scan_at: null,
  schedule_paused_reason: null,
};

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  refresh.mockReset();
});

describe("ScheduleControl", () => {
  it("disables daily and weekly with an explanation until ownership is verified", () => {
    renderWithIntl(<ScheduleControl projectId="p1" verified={false} initial={off} />);
    expect(screen.getByRole("radio", { name: /Daily/ })).toBeDisabled();
    expect(screen.getByRole("radio", { name: /Weekly/ })).toBeDisabled();
    expect(screen.getByRole("radio", { name: /Off/ })).toBeEnabled();
    expect(screen.getByRole("group")).toHaveAccessibleDescription(/Verify ownership above/);
    expect(screen.getByRole("button", { name: "Save schedule" })).toBeDisabled();
  });

  it("shows the next run in UTC", () => {
    renderWithIntl(
      <ScheduleControl
        projectId="p1"
        verified
        initial={{
          scan_frequency: "daily",
          next_scan_at: "2026-11-18T03:25:00Z",
          schedule_paused_reason: null,
        }}
      />,
    );
    expect(screen.getByText(/Next scan: .*2026.*3:25.*\(UTC\)/)).toBeInTheDocument();
  });

  it("shows a paused banner with steps when ownership was lost, and can resume", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse(200, {
        id: "p1",
        scan_frequency: "weekly",
        next_scan_at: "2026-11-24T05:00:00Z",
        schedule_paused_reason: null,
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    renderWithIntl(
      <ScheduleControl
        projectId="p1"
        verified
        initial={{
          scan_frequency: "weekly",
          next_scan_at: "2026-11-17T05:00:00Z",
          schedule_paused_reason: "ownership_lost",
        }}
      />,
    );
    expect(screen.getByText("Automatic scans are paused")).toBeInTheDocument();
    expect(
      screen.getByText(/put the verification file, meta tag or DNS record back/),
    ).toBeVisible();
    expect(screen.queryByText(/Next scan:/)).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Save and resume" }));
    await waitFor(() => expect(screen.getByText("Schedule saved.")).toBeInTheDocument());
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/v1/projects/p1");
    expect(init.method).toBe("PATCH");
    expect(init.body).toBe(JSON.stringify({ scan_frequency: "weekly" }));
    expect((init.headers as Record<string, string>)["X-GuardHub-CSRF"]).toBe("1");
    expect(screen.queryByText("Automatic scans are paused")).toBeNull();
    expect(refresh).toHaveBeenCalled();
  });

  it("maps an API error to localised text", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse(422, { error: { code: "ownership_not_verified", message: "x" } }),
        ),
    );
    renderWithIntl(<ScheduleControl projectId="p1" verified initial={off} />);
    fireEvent.click(screen.getByRole("radio", { name: /Daily/ }));
    fireEvent.click(screen.getByRole("button", { name: "Save schedule" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "We couldn't confirm that you control this website yet.",
    );
  });
});
