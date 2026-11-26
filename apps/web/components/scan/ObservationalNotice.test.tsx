import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import { renderWithIntl } from "@/test/render-with-intl";
import { ObservationalBadge, ObservationalNotice } from "./ObservationalNotice";

describe("Observational scan label", () => {
  it("names the scan as observational and says no active check ran", () => {
    renderWithIntl(
      <>
        <ObservationalBadge />
        <ObservationalNotice />
      </>,
    );
    expect(screen.getByText("Observational scan")).toBeInTheDocument();
    const notice = screen.getByRole("region", { name: "Observational scan" });
    expect(notice).toHaveTextContent("passive observation only");
    expect(notice).toHaveTextContent("Ownership of this site was not proven");
    expect(notice).toHaveTextContent("No active, path-probing or login checks ran");
  });
});
