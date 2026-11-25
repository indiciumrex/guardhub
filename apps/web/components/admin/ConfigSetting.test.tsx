import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithIntl } from "@/test/render-with-intl";
import type { ConfigSetting as Setting } from "@/lib/admin-types";
import { ConfigRevert, ConfigSetting } from "./ConfigSetting";

const router = { push: vi.fn(), refresh: vi.fn() };
vi.mock("next/navigation", () => ({ useRouter: () => router, usePathname: () => "/admin/config" }));

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

const base: Omit<Setting, "key" | "kind" | "value" | "default"> = {
  group: "scans",
  overridden: false,
  minimum: null,
  maximum: null,
  max_length: null,
  updated_at: null,
  updated_by: null,
};
const deadline: Setting = {
  ...base,
  key: "scan.deadline_seconds",
  kind: "int",
  value: 180,
  default: 180,
  minimum: 30,
  maximum: 300,
};
const registration: Setting = {
  ...base,
  group: "flags",
  key: "flags.registration",
  kind: "bool",
  value: true,
  default: true,
};

describe("ConfigSetting", () => {
  it("saves a number inside the bounds, with the reason", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, { ...deadline, value: 240, overridden: true }),
    );
    renderWithIntl(<ConfigSetting setting={deadline} label="Scan time limit (seconds)" />);
    fireEvent.change(screen.getByLabelText("Scan time limit (seconds)"), {
      target: { value: "240" },
    });
    fireEvent.change(screen.getByLabelText("Reason (optional)"), {
      target: { value: "slow targets" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(router.refresh).toHaveBeenCalled());
    expect(sent(0)).toEqual({
      url: "/api/v1/admin/config/settings/scan.deadline_seconds",
      method: "PUT",
      body: { value: 240, reason: "slow targets" },
    });
  });

  it("does not offer to save a value outside the bounds", () => {
    renderWithIntl(<ConfigSetting setting={deadline} label="Scan time limit (seconds)" />);
    fireEvent.change(screen.getByLabelText("Scan time limit (seconds)"), {
      target: { value: "900" },
    });
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    expect(screen.getByText(/Allowed: 30 to 300/)).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("switches a flag off and shows the API's refusal", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(422, { error: { code: "setting_invalid", message: "x" } }),
    );
    renderWithIntl(<ConfigSetting setting={registration} label="New sign-ups" />);
    fireEvent.click(screen.getByRole("switch", { name: "New sign-ups" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "That value is outside the allowed range.",
    );
    expect(sent(0).body).toEqual({ value: false, reason: "" });
  });

  it("offers a reset only when the setting is changed", async () => {
    const { unmount } = renderWithIntl(<ConfigSetting setting={deadline} label="Limit" />);
    expect(screen.queryByRole("button", { name: "Reset to default" })).toBeNull();
    unmount();
    fetchMock.mockResolvedValueOnce(jsonResponse(200, deadline));
    renderWithIntl(
      <ConfigSetting setting={{ ...deadline, value: 240, overridden: true }} label="Limit" />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Reset to default" }));
    await waitFor(() => expect(router.refresh).toHaveBeenCalled());
    expect(sent(0)).toMatchObject({
      url: "/api/v1/admin/config/settings/scan.deadline_seconds/reset",
      method: "POST",
    });
  });
});

describe("ConfigRevert", () => {
  it("reverts one change from the history", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, deadline));
    renderWithIntl(<ConfigRevert changeId={42} />);
    fireEvent.click(screen.getByRole("button", { name: "Revert" }));
    await waitFor(() => expect(router.refresh).toHaveBeenCalled());
    expect(sent(0)).toMatchObject({
      url: "/api/v1/admin/config/history/42/revert",
      method: "POST",
    });
  });
});
