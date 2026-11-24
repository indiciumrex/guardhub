import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithIntl } from "@/test/render-with-intl";
import type { AdminScan, CenterModule, FindingGroup } from "@/lib/admin-types";
import { KillSwitch } from "./KillSwitch";
import { ModuleConfig } from "./ModuleConfig";
import { ScanActions } from "./ScanActions";
import { TriageControl } from "./TriageControl";

const router = { push: vi.fn(), refresh: vi.fn() };
vi.mock("next/navigation", () => ({ useRouter: () => router, usePathname: () => "/admin" }));

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

const scan: AdminScan = {
  id: "0b9b3c8e-2a0f-4c1e-9d65-3c1f0e4e7a11",
  target_url: "https://shop.example.com",
  lifecycle: "running",
  status: "running",
  error: null,
  trigger: "manual",
  kind: "site",
  created_at: "2026-11-25T10:00:00Z",
  started_at: "2026-11-25T10:00:01Z",
  finished_at: null,
  duration_seconds: null,
  checks: 20,
  failed_checks: [],
  score: null,
  project_id: "p1",
  project_name: "Shop",
  owner_email: "a@example.com",
  ownership: { kind: "project", method: "well_known", verified_at: "2026-11-25T09:00:00Z" },
  can_cancel: true,
  can_rerun: false,
};

describe("KillSwitch", () => {
  it("stops everything in one click but needs a second click to release", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { scope: "global", engaged: false }));
    renderWithIntl(<KillSwitch engaged />);
    fireEvent.click(screen.getByRole("button", { name: /Release the kill switch/ }));
    expect(fetchMock).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Yes, release the kill switch" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    expect(sent(0)).toMatchObject({
      method: "POST",
      body: { engaged: false, scan_id: null },
    });
    expect(sent(0).url).toContain("/admin/active/kill");
  });

  it("refuses a malformed scan id without calling the API", () => {
    renderWithIntl(<KillSwitch engaged={false} />);
    fireEvent.change(screen.getByLabelText("Stop one scan (scan id)"), {
      target: { value: "not-a-uuid" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Stop this scan" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Enter a scan id");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("ScanActions", () => {
  it("cancels only after confirmation", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { ...scan, lifecycle: "cancelled" }));
    renderWithIntl(<ScanActions scan={scan} />);
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(fetchMock).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Yes, cancel this scan" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Cancelled."));
    expect(sent(0).url).toContain(`/admin/scans/${scan.id}/cancel`);
    expect(router.refresh).toHaveBeenCalled();
  });

  it("renders nothing for a finished one-time scan", () => {
    const { container } = renderWithIntl(
      <ScanActions scan={{ ...scan, can_cancel: false, can_rerun: false }} />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("shows the API's error", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(409, { error: { code: "scan_not_active", message: "x" } }),
    );
    renderWithIntl(<ScanActions scan={scan} />);
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    fireEvent.click(screen.getByRole("button", { name: "Yes, cancel this scan" }));
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(
        "Only a queued or running scan can be cancelled.",
      ),
    );
  });
});

describe("TriageControl", () => {
  it("sends the chosen review result and note", async () => {
    const group = {
      fingerprint: "f".repeat(64),
      triage: "new",
      triage_note: "",
    } as FindingGroup;
    fetchMock.mockResolvedValue(
      jsonResponse(200, {
        fingerprint: group.fingerprint,
        status: "false_positive",
        note: "lab",
        updated_at: "2026-11-25T10:00:00Z",
      }),
    );
    renderWithIntl(<TriageControl group={group} />);
    fireEvent.change(screen.getByLabelText("Review result"), {
      target: { value: "false_positive" },
    });
    fireEvent.change(screen.getByLabelText("Note"), { target: { value: "lab" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Saved."));
    expect(sent(0)).toMatchObject({
      method: "PUT",
      body: { status: "false_positive", note: "lab" },
    });
    expect(sent(0).url).toContain(`/admin/findings/${group.fingerprint}/triage`);
  });
});

describe("ModuleConfig", () => {
  it("turns maintenance on through the config endpoint", async () => {
    const mod = {
      key: "info_leak",
      min_plan: "free",
      maintenance: false,
    } as CenterModule;
    fetchMock.mockResolvedValue(jsonResponse(200, { ...mod, maintenance: true }));
    renderWithIntl(<ModuleConfig module={mod} />);
    fireEvent.click(screen.getByLabelText("Maintenance (keep out of new scans)"));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    expect(sent(0)).toMatchObject({ method: "PATCH", body: { maintenance: true } });
    expect(sent(0).url).toContain("/admin/modules/info_leak/config");
  });
});
