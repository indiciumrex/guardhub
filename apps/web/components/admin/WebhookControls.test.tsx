import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithIntl } from "@/test/render-with-intl";
import { CreateWebhook, WebhookActions } from "./WebhookControls";

const router = { push: vi.fn(), refresh: vi.fn() };
vi.mock("next/navigation", () => ({
  useRouter: () => router,
  usePathname: () => "/admin/integrations",
}));

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

describe("CreateWebhook", () => {
  it("adds a webhook and shows the signing secret once", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(201, { webhook: { id: "w1", name: "ci" }, secret: "whsec_abc" }),
    );
    renderWithIntl(<CreateWebhook />);
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "ci" } });
    fireEvent.change(screen.getByLabelText("Address"), {
      target: { value: "https://hooks.example.com/in" },
    });
    fireEvent.click(screen.getByLabelText("Test ping"));
    fireEvent.click(screen.getByRole("button", { name: "Add webhook" }));
    expect(await screen.findByLabelText("Signing secret")).toHaveTextContent("whsec_abc");
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/v1/admin/webhooks");
    expect(JSON.parse(String(init.body))).toEqual({
      name: "ci",
      url: "https://hooks.example.com/in",
      events: ["scan.completed", "ping"],
    });
  });

  it("does not offer to add a plain http address", () => {
    renderWithIntl(<CreateWebhook />);
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "ci" } });
    fireEvent.change(screen.getByLabelText("Address"), {
      target: { value: "http://hooks.example.com/in" },
    });
    expect(screen.getByRole("button", { name: "Add webhook" })).toBeDisabled();
  });
});

describe("WebhookActions", () => {
  it("sends a test ping and switches the webhook off", async () => {
    fetchMock.mockImplementation(async () => jsonResponse(202, {}));
    renderWithIntl(<WebhookActions webhookId="w1" name="ci" enabled />);
    fireEvent.click(screen.getByRole("button", { name: "Send a test to webhook ci" }));
    await waitFor(() => expect(router.refresh).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole("button", { name: "Switch off webhook ci" }));
    await waitFor(() => expect(router.refresh).toHaveBeenCalledTimes(2));
    const calls = fetchMock.mock.calls.map(([u, i]) => [u, JSON.parse(String(i.body ?? "null"))]);
    expect(calls).toEqual([
      ["/api/v1/admin/webhooks/w1/ping", null],
      ["/api/v1/admin/webhooks/w1/enabled", { enabled: false }],
    ]);
  });
});
