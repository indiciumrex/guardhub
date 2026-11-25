import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithIntl } from "@/test/render-with-intl";
import { CreateApiKey, RevokeApiKey } from "./ApiKeyControls";

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

const secret = "ghk_" + "a".repeat(43);

describe("CreateApiKey", () => {
  it("creates a key with the chosen scopes and shows the secret once", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(201, {
        key: { id: "k1", name: "ci", prefix: secret.slice(0, 12), status: "active" },
        secret,
      }),
    );
    renderWithIntl(<CreateApiKey />);
    expect(screen.getByRole("button", { name: "Create key" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "ci" } });
    fireEvent.click(screen.getByLabelText("Start scans"));
    fireEvent.change(screen.getByLabelText("Expires in"), { target: { value: "30" } });
    fireEvent.click(screen.getByRole("button", { name: "Create key" }));
    expect(await screen.findByLabelText("New API key")).toHaveTextContent(secret);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/v1/admin/integrations/keys");
    expect(JSON.parse(String(init.body))).toEqual({
      name: "ci",
      scopes: ["scans:read", "scans:trigger"],
      expires_in_days: 30,
    });
    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    expect(screen.queryByText(secret)).toBeNull();
  });

  it("needs at least one scope", () => {
    renderWithIntl(<CreateApiKey />);
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "ci" } });
    fireEvent.click(screen.getByLabelText("Read scans"));
    expect(screen.getByRole("button", { name: "Create key" })).toBeDisabled();
  });
});

describe("RevokeApiKey", () => {
  it("revokes a key", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { id: "k1", status: "revoked" }));
    renderWithIntl(<RevokeApiKey keyId="k1" name="ci" />);
    fireEvent.click(screen.getByRole("button", { name: "Revoke key ci" }));
    await waitFor(() => expect(router.refresh).toHaveBeenCalled());
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/v1/admin/integrations/keys/k1/revoke");
    expect(init.method).toBe("POST");
  });
});
