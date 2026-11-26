import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithIntl } from "@/test/render-with-intl";
import { AssignPlan, PlanEditor, StartTrial } from "./BillingControls";

const router = { push: vi.fn(), refresh: vi.fn() };
vi.mock("next/navigation", () => ({ useRouter: () => router, usePathname: () => "/" }));

let fetchMock: ReturnType<typeof vi.fn>;
beforeEach(() => {
  fetchMock = vi.fn(
    async () =>
      new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } }),
  );
  vi.stubGlobal("fetch", fetchMock);
  router.refresh.mockReset();
});
afterEach(() => vi.unstubAllGlobals());

const sent = (i: number) => {
  const [url, init] = fetchMock.mock.calls[i] as [string, RequestInit];
  return { url, method: init.method, body: JSON.parse(String(init.body)) };
};

describe("billing controls", () => {
  it("starts a trial", async () => {
    renderWithIntl(<StartTrial plan="pro" days={14} label="Pro" />);
    fireEvent.click(screen.getByRole("button", { name: "Start a 14-day trial of Pro" }));
    await waitFor(() => expect(router.refresh).toHaveBeenCalled());
    expect(sent(0)).toEqual({
      url: "/api/v1/billing/trial",
      method: "POST",
      body: { plan: "pro" },
    });
  });

  it("saves plan limits; the free plan has no trial and stays public", async () => {
    renderWithIntl(
      <PlanEditor
        label="Free"
        plan={{
          key: "free",
          rank: 0,
          max_sites: 25,
          scans_per_day: 1000,
          concurrent_scans: 25,
          trial_days: 0,
          public: true,
        }}
      />,
    );
    expect(screen.getByLabelText("Trial days")).toBeDisabled();
    expect(screen.getByLabelText("Public")).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Websites"), { target: { value: "3" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(router.refresh).toHaveBeenCalled());
    expect(sent(0)).toEqual({
      url: "/api/v1/admin/billing/plans/free",
      method: "PUT",
      body: {
        max_sites: 3,
        scans_per_day: 1000,
        concurrent_scans: 25,
        trial_days: 0,
        public: true,
      },
    });
  });

  it("assigns a plan by e-mail with a reason", async () => {
    renderWithIntl(<AssignPlan />);
    fireEvent.change(screen.getByLabelText("Account e-mail"), {
      target: { value: "c@example.com" },
    });
    fireEvent.change(screen.getByLabelText("Plan"), { target: { value: "agency" } });
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "invoice 42" } });
    fireEvent.click(screen.getByRole("button", { name: "Assign" }));
    await waitFor(() => expect(router.refresh).toHaveBeenCalled());
    expect(sent(0).body).toEqual({ email: "c@example.com", plan: "agency", reason: "invoice 42" });
  });
});
