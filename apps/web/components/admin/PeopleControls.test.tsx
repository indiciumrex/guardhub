import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithIntl } from "@/test/render-with-intl";
import { AcceptAdminInvite, AccountActions, InviteAdmin } from "./PeopleControls";

const router = { push: vi.fn(), refresh: vi.fn() };
vi.mock("next/navigation", () => ({
  useRouter: () => router,
  usePathname: () => "/admin/users",
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
  router.push.mockReset();
});
afterEach(() => vi.unstubAllGlobals());

const call = (i: number) => {
  const [url, init] = fetchMock.mock.calls[i] as [string, RequestInit];
  return {
    url,
    method: init.method ?? "GET",
    body: init.body ? JSON.parse(String(init.body)) : null,
  };
};

describe("AccountActions", () => {
  it("disables an account with a reason", async () => {
    fetchMock.mockImplementation(async () => jsonResponse(200, { id: "u1", disabled_at: "x" }));
    renderWithIntl(
      <AccountActions userId="u1" email="a@example.com" disabled={false} isSelf={false} />,
    );
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "abuse" } });
    fireEvent.click(screen.getByRole("button", { name: "Disable a@example.com" }));
    await waitFor(() => expect(router.refresh).toHaveBeenCalled());
    expect(call(0)).toEqual({
      url: "/api/v1/admin/people/u1/disable",
      method: "POST",
      body: { reason: "abuse" },
    });
  });

  it("never offers to disable yourself", () => {
    renderWithIntl(<AccountActions userId="me" email="me@example.com" disabled={false} isSelf />);
    expect(screen.queryByRole("button", { name: /^Disable/ })).toBeNull();
  });

  it("lists sessions and ends one", async () => {
    const one = {
      jti: "j1",
      issued_at: 1800000000,
      expires_at: 1800028800,
      ip_hash: "abc",
      client: "Firefox · Linux",
    };
    fetchMock
      .mockImplementationOnce(async () => jsonResponse(200, [one]))
      .mockImplementationOnce(async () => jsonResponse(200, { sessions_ended: 1 }))
      .mockImplementationOnce(async () => jsonResponse(200, []));
    renderWithIntl(<AccountActions userId="u1" email="a@example.com" disabled isSelf={false} />);
    fireEvent.click(screen.getByRole("button", { name: "Sessions of a@example.com" }));
    expect(await screen.findByText("Firefox · Linux")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "End" }));
    expect(await screen.findByText("No active sessions.")).toBeInTheDocument();
    expect(call(1)).toEqual({
      url: "/api/v1/admin/people/u1/sessions/end",
      method: "POST",
      body: { jti: "j1" },
    });
  });
});

describe("InviteAdmin", () => {
  it("shows the one-time link", async () => {
    const link = "https://guardhub.dev/account/admin-invite?token=ghi_x";
    fetchMock.mockImplementation(async () => jsonResponse(201, { invite: {}, link }));
    renderWithIntl(<InviteAdmin />);
    fireEvent.change(screen.getByLabelText("E-mail address"), {
      target: { value: "b@example.com" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create invitation" }));
    expect(await screen.findByLabelText("Invitation link")).toHaveTextContent(link);
    expect(call(0).body).toEqual({ email: "b@example.com" });
  });
});

describe("AcceptAdminInvite", () => {
  it("accepts and opens the console", async () => {
    fetchMock.mockImplementation(async () => jsonResponse(200, { role: "admin" }));
    renderWithIntl(<AcceptAdminInvite token="ghi_x" />);
    fireEvent.click(screen.getByRole("button", { name: "Accept and open the admin console" }));
    await waitFor(() => expect(router.push).toHaveBeenCalledWith("/admin"));
    expect(call(0)).toEqual({
      url: "/api/v1/auth/admin-invite/accept",
      method: "POST",
      body: { token: "ghi_x" },
    });
  });
});
