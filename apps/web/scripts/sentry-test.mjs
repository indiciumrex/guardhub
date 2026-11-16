/**
 * Sends ONE error-tracking test event from the web container and waits for the server's answer.
 * Runs inside the container only (no HTTP route, so no public attack surface):
 *   docker compose exec web node apps/web/scripts/sentry-test.mjs
 * Uses the same SDK, DSN, environment, release and service tag as the web server.
 * Exit codes: 0 accepted (prints the event id), 1 delivery failed, 2 no DSN set.
 */
import * as Sentry from "@sentry/node";

const dsn = (process.env.SENTRY_DSN_WEB?.trim() || process.env.SENTRY_DSN?.trim()) ?? "";
if (!dsn) {
  console.log(
    "SENTRY_DSN_WEB (or SENTRY_DSN) is not set; error tracking is off. Nothing was sent.",
  );
  process.exit(2);
}

const statuses = [];
const failures = [];

Sentry.init({
  dsn,
  environment: process.env.SENTRY_ENVIRONMENT?.trim() || "production",
  release: process.env.GUARDHUB_VERSION?.trim() || undefined,
  sendDefaultPii: false,
  skipOpenTelemetrySetup: true,
  registerEsmLoaderHooks: false,
  defaultIntegrations: false,
  initialScope: { tags: { service: "web", runtime: "node" } },
  // Same HTTP transport as the server, observed so a rejection is a failure, not a silent drop.
  transport: (options) => {
    const transport = Sentry.makeNodeTransport(options);
    return {
      ...transport,
      send: async (envelope) => {
        try {
          const response = await transport.send(envelope);
          statuses.push(response.statusCode ?? 0);
          return response;
        } catch (error) {
          failures.push(error instanceof Error ? error.message : String(error));
          throw error;
        }
      },
    };
  },
});

const eventId = Sentry.captureMessage("GuardHub Sentry test event (service=web)", "error");
await Sentry.flush(10_000);

const rejected = statuses.find((s) => s < 200 || s > 299);
if (failures.length || rejected !== undefined || statuses.length === 0) {
  const reason = failures[0]
    ? `network error: ${failures[0]}`
    : rejected !== undefined
      ? `server answered HTTP ${rejected}`
      : "nothing was sent before the timeout";
  console.log(`Delivery FAILED (${reason}).`);
  process.exit(1);
}
console.log(`Sent test event ${eventId} (service=web); the server accepted it.`);
console.log("Find it in Sentry by searching for this event id.");
process.exit(0);
