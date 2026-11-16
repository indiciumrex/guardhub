/**
 * Next.js configuration for the GuardHub web app.
 * - Rewrites /api/* to the FastAPI service so the session cookie stays first-party.
 * - Sets the static security headers. The Content-Security-Policy is per-request (nonce)
 *   and is therefore set in middleware.ts, not here.
 */
import path from "node:path";
import type { NextConfig } from "next";
import createNextIntlPlugin from "next-intl/plugin";

const withNextIntl = createNextIntlPlugin("./i18n/request.ts");

// NOTE: rewrites are compiled into the build output, so API_INTERNAL_URL must be set at
// build time (the Dockerfile exposes it as a build ARG, default http://api:8000).
const apiInternalUrl = (process.env.API_INTERNAL_URL ?? "http://api:8000").replace(/\/+$/, "");

const baseSecurityHeaders = [
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  {
    key: "Permissions-Policy",
    value:
      "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), browsing-topics=()",
  },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
];

// Scan reports, account and admin pages never leak their URL to other origins.
const noReferrer = [{ key: "Referrer-Policy", value: "no-referrer" }];

const nextConfig: NextConfig = {
  output: "standalone",
  // Monorepo: trace files from the repo root so packages/shared is resolvable.
  outputFileTracingRoot: path.join(__dirname, "../.."),
  poweredByHeader: false,
  reactStrictMode: true,
  // Error tracking SDK (loaded only when SENTRY_DSN is set): required from node_modules at
  // runtime instead of being bundled, which keeps OpenTelemetry/require-hook code out of webpack.
  serverExternalPackages: ["@sentry/node"],
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${apiInternalUrl}/api/:path*` }];
  },
  async headers() {
    // When two rules set the same key, the later rule wins.
    return [
      { source: "/:path*", headers: baseSecurityHeaders },
      { source: "/scan", headers: noReferrer },
      { source: "/scan/:path*", headers: noReferrer },
      { source: "/account/:path*", headers: noReferrer },
      { source: "/admin", headers: noReferrer },
      { source: "/admin/:path*", headers: noReferrer },
    ];
  },
};

export default withNextIntl(nextConfig);
