import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { renderWithIntl } from "@/test/render-with-intl";
import { isSlackWebhookUrl, type NotificationSettings } from "@/lib/types";
import { NotificationSettingsForm } from "./NotificationSettingsForm";
import { NotificationTestButtons } from "./NotificationTestButtons";
import { NotificationHistory } from "./NotificationHistory";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn(), push: vi.fn() }),
}));

const VALID_HOOK = "https://hooks.slack.com/services/T000/B000/abcdefghij";

const settings: NotificationSettings = {
  email_enabled: true,
  notify_new: true,
  notify_regression: true,
  notify_fixed: false,
  slack_configured: false,
  email: "owner@example.com",
};

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function sentBody(mock: ReturnType<typeof vi.fn>): Record<string, unknown> {
  const call = mock.mock.calls.at(-1) as [string, RequestInit];
  return JSON.parse(call[1].body as string) as Record<string, unknown>;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("isSlackWebhookUrl", () => {
  it("matches the contract pattern", () => {
    expect(isSlackWebhookUrl(VALID_HOOK)).toBe(true);
    expect(isSlackWebhookUrl("http://hooks.slack.com/services/T000/B000/abcdefghij")).toBe(false);
    expect(isSlackWebhookUrl("https://hooks.slack.com.evil.io/services/T000/B000/abc")).toBe(false);
    expect(isSlackWebhookUrl("https://hooks.slack.com/services/short")).toBe(false);
  });
});

describe("NotificationSettingsForm", () => {
  it("shows the toggles and the user's e-mail", () => {
    renderWithIntl(<NotificationSettingsForm initial={settings} />);
    expect(screen.getByLabelText("Send alerts by e-mail to owner@example.com")).toBeChecked();
    expect(screen.getByLabelText("New issues")).toBeChecked();
    expect(screen.getByLabelText("Issues that came back")).toBeChecked();
    expect(screen.getByLabelText("A short summary when issues are fixed")).not.toBeChecked();
  });

  it("blocks an invalid Slack URL with a hint and does not call the API", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    renderWithIntl(<NotificationSettingsForm initial={settings} />);
    const field = screen.getByLabelText("Slack incoming webhook address");
    fireEvent.change(field, { target: { value: "https://example.com/hook" } });
    fireEvent.click(screen.getByRole("button", { name: "Save alert settings" }));
    expect(fetchMock).not.toHaveBeenCalled();
    expect(field).toHaveAttribute("aria-invalid", "true");
    expect(field).toHaveAccessibleDescription(/doesn't look like a Slack incoming webhook/);
  });

  it("sends a new webhook once, then clears the field and shows only the connected state", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(jsonResponse(200, { ...settings, slack_configured: true }));
    vi.stubGlobal("fetch", fetchMock);
    renderWithIntl(<NotificationSettingsForm initial={settings} />);
    fireEvent.change(screen.getByLabelText("Slack incoming webhook address"), {
      target: { value: VALID_HOOK },
    });
    fireEvent.click(screen.getByLabelText("A short summary when issues are fixed"));
    fireEvent.click(screen.getByRole("button", { name: "Save alert settings" }));

    await waitFor(() => expect(screen.getByText("Alert settings saved.")).toBeInTheDocument());
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/v1/account/notifications");
    expect(init.method).toBe("PUT");
    expect((init.headers as Record<string, string>)["X-GuardHub-CSRF"]).toBe("1");
    expect(sentBody(fetchMock)).toEqual({
      email_enabled: true,
      notify_new: true,
      notify_regression: true,
      notify_fixed: true,
      slack_webhook_url: VALID_HOOK,
    });
    expect(screen.getByText("Slack is connected.")).toBeInTheDocument();
    expect(screen.queryByLabelText("Slack incoming webhook address")).toBeNull();
    expect(document.body.innerHTML).not.toContain("T000/B000");
  });

  it("never shows a stored webhook; keep omits the key, remove sends null", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(jsonResponse(200, { ...settings, slack_configured: true }));
    vi.stubGlobal("fetch", fetchMock);
    renderWithIntl(<NotificationSettingsForm initial={{ ...settings, slack_configured: true }} />);
    expect(screen.getByText("Slack is connected.")).toBeInTheDocument();
    expect(screen.queryByRole("textbox")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Save alert settings" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    expect(sentBody(fetchMock)).not.toHaveProperty("slack_webhook_url");

    fireEvent.click(screen.getByRole("button", { name: "Replace webhook" }));
    expect(screen.getByLabelText("Slack incoming webhook address")).toHaveValue("");
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));

    fetchMock.mockResolvedValue(jsonResponse(200, { ...settings, slack_configured: false }));
    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    expect(screen.getByText("Slack will be disconnected when you save.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Save alert settings" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    expect(sentBody(fetchMock)).toHaveProperty("slack_webhook_url", null);
    expect(await screen.findByText("Slack isn't connected.")).toBeInTheDocument();
  });

  it("marks the field when the server rejects the webhook", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse(422, { error: { code: "invalid_slack_webhook", message: "bad" } }),
        ),
    );
    renderWithIntl(<NotificationSettingsForm initial={settings} />);
    const field = screen.getByLabelText("Slack incoming webhook address");
    fireEvent.change(field, { target: { value: VALID_HOOK } });
    fireEvent.click(screen.getByRole("button", { name: "Save alert settings" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "That isn't a Slack incoming webhook address.",
    );
    expect(field).toHaveAttribute("aria-invalid", "true");
  });
});

describe("NotificationTestButtons", () => {
  it("disables the Slack test until Slack is connected", () => {
    renderWithIntl(<NotificationTestButtons slackConfigured={false} />);
    const slack = screen.getByRole("button", { name: "Send test to Slack" });
    expect(slack).toBeDisabled();
    expect(slack).toHaveAccessibleDescription("Connect Slack and save before sending a test.");
    expect(screen.getByRole("button", { name: "Send test e-mail" })).toBeEnabled();
  });

  it("confirms a sent test and posts the channel with the CSRF header", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 202 }));
    vi.stubGlobal("fetch", fetchMock);
    renderWithIntl(<NotificationTestButtons slackConfigured />);
    fireEvent.click(screen.getByRole("button", { name: "Send test to Slack" }));
    expect(await screen.findByText(/Test sent/)).toBeInTheDocument();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/v1/account/notifications/test");
    expect(init.body).toBe(JSON.stringify({ channel: "slack" }));
    expect((init.headers as Record<string, string>)["X-GuardHub-CSRF"]).toBe("1");
  });

  it("explains the hourly limit on 429", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(jsonResponse(429, { error: { code: "rate_limited", message: "slow" } })),
    );
    renderWithIntl(<NotificationTestButtons slackConfigured={false} />);
    fireEvent.click(screen.getByRole("button", { name: "Send test e-mail" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "You can send 3 tests per hour. Please wait a while and try again.",
    );
  });

  it("explains the hourly limit in Turkish", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(jsonResponse(429, { error: { code: "rate_limited", message: "slow" } })),
    );
    renderWithIntl(<NotificationTestButtons slackConfigured={false} />, "tr");
    fireEvent.click(screen.getByRole("button", { name: "Deneme e-postası gönder" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Saatte en fazla 3 deneme");
  });
});

describe("NotificationHistory", () => {
  it("shows an empty state", () => {
    renderWithIntl(<NotificationHistory items={[]} projectNames={{}} />);
    expect(screen.getByText(/No alerts yet/)).toBeInTheDocument();
  });

  it("lists alerts with text status and a link to the changes", () => {
    renderWithIntl(
      <NotificationHistory
        projectNames={{ p1: "Main site" }}
        items={[
          {
            id: "n1",
            scan_id: "s9",
            project_id: "p1",
            channel: "email",
            status: "sent",
            new_count: 2,
            regression_count: 1,
            fixed_count: 0,
            created_at: "2026-11-16T08:00:00Z",
            sent_at: "2026-11-16T08:00:05Z",
          },
          {
            id: "n2",
            scan_id: "s8",
            project_id: null,
            channel: "slack",
            status: "failed",
            new_count: 0,
            regression_count: 0,
            fixed_count: 3,
            created_at: "2026-11-15T08:00:00Z",
            sent_at: null,
          },
        ]}
      />,
    );
    const table = screen.getByRole("table", { name: /Alerts we sent/ });
    const rows = within(table).getAllByRole("row");
    expect(rows[1]).toHaveTextContent("Main site");
    expect(rows[1]).toHaveTextContent("2 new, 1 came back, 0 fixed");
    expect(rows[1]).toHaveTextContent("Sent");
    expect(within(rows[1]!).getByRole("link", { name: /View changes/ })).toHaveAttribute(
      "href",
      "/account/projects/p1/compare/s9",
    );
    expect(rows[2]).toHaveTextContent("Deleted project");
    expect(rows[2]).toHaveTextContent("Failed");
    expect(within(rows[2]!).queryByRole("link")).toBeNull();
  });
});
