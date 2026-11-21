import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithIntl } from "@/test/render-with-intl";
import { GitHubSection } from "./GitHubSection";
import { GitHubCallback } from "./GitHubCallback";

const replace = vi.fn();
const push = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn(), push, replace }),
}));

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  replace.mockReset();
  push.mockReset();
});

describe("GitHubSection", () => {
  it("says so when GitHub is not configured, without a connect button", () => {
    renderWithIntl(<GitHubSection status={{ configured: false, installations: [] }} />);
    expect(screen.getByText("Connecting GitHub is not available yet.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Connect GitHub" })).toBeNull();
  });

  it("lists the shared repositories and adds one as a project", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(200, [
          { repo_id: 1, full_name: "acme/api", private: true, project_id: null },
          { repo_id: 2, full_name: "acme/web", private: false, project_id: "p-web" },
        ]),
      )
      .mockResolvedValueOnce(jsonResponse(201, { id: "p-api" }));
    vi.stubGlobal("fetch", fetchMock);
    renderWithIntl(
      <GitHubSection
        status={{
          configured: true,
          installations: [
            { id: "i1", account_login: "acme", account_type: "Organization", created_at: "x" },
          ],
        }}
      />,
    );
    expect(screen.getByText("GitHub account acme")).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /Change which repositories GuardHub can read/ }),
    ).toHaveAttribute("href", "https://github.com/organizations/acme/settings/installations");
    fireEvent.click(screen.getByRole("button", { name: "Choose repositories" }));
    await screen.findByText("acme/api");
    expect(screen.getByRole("link", { name: "Open project" })).toHaveAttribute(
      "href",
      "/account/projects/p-web",
    );
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    await waitFor(() => expect(push).toHaveBeenCalledWith("/account/projects/p-api"));
    const [url, init] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(url).toContain("/api/v1/github/installations/i1/repositories");
    expect(JSON.parse(String(init.body))).toEqual({ repo_id: 1 });
  });
});

describe("GitHubCallback", () => {
  it("completes the installation once and returns to the account page", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(201, { id: "i1" }));
    vi.stubGlobal("fetch", fetchMock);
    renderWithIntl(
      <GitHubCallback
        code="abc"
        installationId="42"
        state={"s".repeat(20)}
        setupAction="install"
      />,
    );
    await waitFor(() => expect(replace).toHaveBeenCalledWith("/account#github"));
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(String(init.body))).toEqual({
      code: "abc",
      installation_id: 42,
      state: "s".repeat(20),
    });
  });

  it("explains a pending organisation approval and calls nothing", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    renderWithIntl(
      <GitHubCallback code={null} installationId={null} state={null} setupAction="request" />,
    );
    expect(screen.getByText(/must approve GuardHub/)).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses an incomplete link", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    renderWithIntl(
      <GitHubCallback code="abc" installationId="not-a-number" state="x" setupAction={null} />,
    );
    expect(screen.getByRole("alert")).toHaveTextContent("This link is incomplete");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
