/**
 * Same-origin tunnel for browser error events (see lib/observability/tunnel.ts). Returns 404
 * unless SENTRY_DSN_WEB (or SENTRY_DSN) is set and SENTRY_BROWSER is not "off". POST only.
 */
import { tunnelPost } from "@/lib/observability/tunnel";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request: Request): Promise<Response> {
  return tunnelPost(request);
}
