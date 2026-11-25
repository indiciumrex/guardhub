import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithIntl } from "@/test/render-with-intl";
import type { OpsAlertRule } from "@/lib/admin-types";
import { OpsAlertActions, OpsAlertRuleForm } from "./OpsAlertControls";

const router = { push: vi.fn(), refresh: vi.fn() };
vi.mock("next/navigation", () => ({ useRouter: () => router, usePathname: () => "/admin/alerts" }));

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

let fetchMock: ReturnType<typeof vi.fn>;
beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
  router.refresh.mockReset();
});
afterEach(() => vi.unstubAllGlobals());

function sent(call: number): { url: string; method: string; body: unknown } {
  const [url, init] = fetchMock.mock.calls[call] as [string, RequestInit];
  return {
    url,
    method: init.method ?? "GET",
    body: init.body ? JSON.parse(String(init.body)) : null,
  };
}

const rule: OpsAlertRule = {
  kind: "scan_failures",
  enabled: true,
  threshold: 5,
  window_minutes: 30,
  email: true,
  muted_until: null,
  escalate_after_minutes: 60,
  updated_at: "2026-11-26T10:00:00Z",
};

describe("OpsAlertRuleForm", () => {
  it("saves threshold, window, e-mail and escalation", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, rule));
    renderWithIntl(<OpsAlertRuleForm rule={rule} label="Scan failures" />);
    fireEvent.change(screen.getByLabelText("Alert at (failed scans)"), { target: { value: "3" } });
    fireEvent.change(screen.getByLabelText("Escalate after (minutes)"), { target: { value: "" } });
    fireEvent.click(screen.getByLabelText("E-mail admins"));
    fireEvent.click(screen.getByRole("button", { name: "Save rule" }));
    await waitFor(() => expect(router.refresh).toHaveBeenCalled());
    expect(sent(0)).toEqual({
      url: "/api/v1/admin/alerts/rules/scan_failures",
      method: "PUT",
      body: {
        enabled: true,
        threshold: 3,
        window_minutes: 30,
        email: false,
        escalate_after_minutes: null,
      },
    });
  });

  it("does not offer to save a threshold out of range", () => {
    renderWithIntl(<OpsAlertRuleForm rule={rule} label="Scan failures" />);
    fireEvent.change(screen.getByLabelText("Alert at (failed scans)"), { target: { value: "0" } });
    expect(screen.getByRole("button", { name: "Save rule" })).toBeDisabled();
  });

  it("has no window for the scanner-offline rule, and mutes for an hour", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, rule));
    renderWithIntl(
      <OpsAlertRuleForm rule={{ ...rule, kind: "worker_offline" }} label="Scanner offline" />,
    );
    expect(screen.queryByLabelText("Window (minutes)")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "1 hour" }));
    await waitFor(() => expect(router.refresh).toHaveBeenCalled());
    expect(sent(0)).toEqual({
      url: "/api/v1/admin/alerts/rules/worker_offline/mute",
      method: "POST",
      body: { minutes: 60 },
    });
  });
});

describe("OpsAlertActions", () => {
  it("acknowledges, and shows the API's refusal", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(422, { error: { code: "alert_resolved", message: "x" } }),
    );
    renderWithIntl(<OpsAlertActions alertId="a1" acknowledged={false} />);
    fireEvent.click(screen.getByRole("button", { name: "Acknowledge" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("This alert is already resolved.");
    expect(sent(0)).toMatchObject({ url: "/api/v1/admin/alerts/a1/acknowledge", method: "POST" });
  });

  it("offers only resolve once acknowledged", () => {
    renderWithIntl(<OpsAlertActions alertId="a1" acknowledged />);
    expect(screen.queryByRole("button", { name: "Acknowledge" })).toBeNull();
    expect(screen.getByRole("button", { name: "Resolve" })).toBeInTheDocument();
  });
});
