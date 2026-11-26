import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithIntl } from "@/test/render-with-intl";
import { StartCheckout } from "./BillingControls";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), refresh: vi.fn() }),
  usePathname: () => "/account/plan/checkout",
}));

const assign = vi.fn();
let reply: { status: number; body: object };
beforeEach(() => {
  assign.mockReset();
  vi.stubGlobal("location", { ...window.location, assign });
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(JSON.stringify(reply.body), {
          status: reply.status,
          headers: { "Content-Type": "application/json" },
        }),
    ),
  );
});
afterEach(() => vi.unstubAllGlobals());

describe("StartCheckout", () => {
  it("opens the provider's page the API returns", async () => {
    reply = { status: 200, body: { url: "https://checkout.stripe.com/c/pay/cs_test_1" } };
    renderWithIntl(<StartCheckout plan="pro" label="Pro" />);
    fireEvent.click(screen.getByRole("button", { name: "Continue to payment for Pro" }));
    await waitFor(() =>
      expect(assign).toHaveBeenCalledWith("https://checkout.stripe.com/c/pay/cs_test_1"),
    );
  });

  it("never follows another address, and shows the refusal while charging is off", async () => {
    reply = { status: 200, body: { url: "https://evil.example/pay" } };
    renderWithIntl(<StartCheckout plan="pro" label="Pro" />);
    fireEvent.click(screen.getByRole("button", { name: "Continue to payment for Pro" }));
    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
    expect(assign).not.toHaveBeenCalled();

    reply = {
      status: 409,
      body: { error: { code: "billing_not_live", message: "Payments are not switched on." } },
    };
    fireEvent.click(screen.getByRole("button", { name: "Continue to payment for Pro" }));
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent("Payments are not switched on."),
    );
    expect(assign).not.toHaveBeenCalled();
  });
});
