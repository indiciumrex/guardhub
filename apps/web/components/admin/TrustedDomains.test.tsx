import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { renderWithIntl } from "@/test/render-with-intl";
import type { TrustedDomain } from "@/lib/types";
import { TrustedDomainCard, TrustedDomainList, TrustedDomainStatusChip } from "./TrustedDomains";

const router = { push: vi.fn(), refresh: vi.fn() };
vi.mock("next/navigation", () => ({ useRouter: () => router }));

function domain(overrides: Partial<TrustedDomain> = {}): TrustedDomain {
  return {
    id: "d1",
    host: "example.com",
    target_origin: "https://example.com",
    status: "pending",
    verification: {
      token: "ghv_tok123",
      well_known_url: "https://example.com/.well-known/guardhub-verify.txt",
      meta_tag: '<meta name="guardhub-verification" content="ghv_tok123">',
      dns_name: "_guardhub.example.com",
      dns_value: "guardhub-verify=ghv_tok123",
    },
    method: null,
    verified_at: null,
    last_checked_at: null,
    suspended_at: null,
    created_at: "2026-11-17T10:00:00Z",
    ...overrides,
  };
}

const active = domain({
  status: "active",
  method: "well_known",
  verified_at: "2026-11-17T10:05:00Z",
  last_checked_at: "2026-11-17T10:05:00Z",
});

function jsonResponse(status: number, body: unknown): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
  router.push.mockReset();
  router.refresh.mockReset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("TrustedDomainStatusChip", () => {
  it("shows each status as text", () => {
    renderWithIntl(
      <>
        <TrustedDomainStatusChip status="pending" />
        <TrustedDomainStatusChip status="active" />
        <TrustedDomainStatusChip status="suspended" />
      </>,
    );
    expect(screen.getByText("Pending")).toBeInTheDocument();
    expect(screen.getByText("Active")).toBeInTheDocument();
    expect(screen.getByText("Suspended")).toBeInTheDocument();
  });

  it("is localised in Turkish", () => {
    renderWithIntl(<TrustedDomainStatusChip status="suspended" />, "tr");
    expect(screen.getByText("Askıya alındı")).toBeInTheDocument();
  });
});

describe("TrustedDomainCard", () => {
  it("shows ownership instructions for a pending domain, and no Scan now", () => {
    renderWithIntl(<TrustedDomainCard domain={domain()} />);
    expect(
      screen.getByRole("heading", { name: "Prove that you control example.com" }),
    ).toBeVisible();
    expect(screen.getByDisplayValue(domain().verification.well_known_url)).toBeInTheDocument();
    expect(screen.getByDisplayValue("guardhub-verify=ghv_tok123")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Verify" })).toBeEnabled();
    expect(screen.queryByRole("button", { name: "Scan now" })).toBeNull();
  });

  it("hides the instructions for an active domain and offers Scan now", () => {
    renderWithIntl(<TrustedDomainCard domain={active} />);
    expect(screen.queryByDisplayValue(active.verification.well_known_url)).toBeNull();
    expect(screen.getByText("Active")).toBeInTheDocument();
    expect(screen.getByText(/verification file/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check again" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Scan now" })).toBeEnabled();
  });

  it("keeps a suspended domain's instructions one click away and doesn't offer a scan", () => {
    renderWithIntl(<TrustedDomainCard domain={{ ...active, status: "suspended" }} />);
    expect(
      screen.getByText("Show how to publish the proof again").closest("details"),
    ).not.toHaveAttribute("open");
    expect(screen.queryByRole("button", { name: "Scan now" })).toBeNull();
  });

  it("asks for an in-page confirmation before removing", async () => {
    const confirmSpy = vi.spyOn(window, "confirm");
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }));
    renderWithIntl(<TrustedDomainCard domain={active} />);

    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    const confirmBox = screen.getByRole("group", { name: "Confirm removal" });
    expect(confirmBox).toHaveTextContent("Remove example.com from your trusted domains?");
    expect(fetchMock).not.toHaveBeenCalled();

    fireEvent.click(within(confirmBox).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("group", { name: "Confirm removal" })).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    fireEvent.click(screen.getByRole("button", { name: "Yes, remove it" }));
    await waitFor(() => expect(router.refresh).toHaveBeenCalled());
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/v1/admin/trusted-domains/d1");
    expect(init.method).toBe("DELETE");
    expect((init.headers as Record<string, string>)["X-GuardHub-CSRF"]).toBe("1");
    expect(confirmSpy).not.toHaveBeenCalled();
  });

  it("Scan now starts a scan and opens its page", async () => {
    fetchMock.mockResolvedValue(jsonResponse(202, { id: "scan-42" }));
    renderWithIntl(<TrustedDomainCard domain={active} />);
    fireEvent.click(screen.getByRole("button", { name: "Scan now" }));
    await waitFor(() => expect(router.push).toHaveBeenCalledWith("/account/scans/scan-42"));
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/v1/admin/trusted-domains/d1/scan");
    expect(init.method).toBe("POST");
  });

  it("shows a localised error when the domain is no longer active", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(422, { error: { code: "trusted_domain_inactive", message: "x" } }),
    );
    renderWithIntl(<TrustedDomainCard domain={active} />);
    fireEvent.click(screen.getByRole("button", { name: "Scan now" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The trusted domain for this site isn't active right now.",
    );
    expect(router.push).not.toHaveBeenCalled();
  });
});

describe("TrustedDomainList", () => {
  it("says so when there are no domains", () => {
    renderWithIntl(<TrustedDomainList domains={[]} />);
    expect(screen.getByText("You haven't added any trusted domains yet.")).toBeInTheDocument();
  });

  it("renders one card per domain", () => {
    renderWithIntl(
      <TrustedDomainList domains={[domain(), { ...active, id: "d2", host: "app.example.com" }]} />,
    );
    expect(screen.getByRole("heading", { name: "example.com" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "app.example.com" })).toBeInTheDocument();
    expect(screen.getAllByRole("group", { name: /^Actions for / })).toHaveLength(2);
  });
});
