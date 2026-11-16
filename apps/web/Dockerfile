# GuardHub web (Next.js standalone). Build from the REPO ROOT so packages/shared is available:
#   docker build -f apps/web/Dockerfile -t guardhub-web .
# API_INTERNAL_URL is baked into the /api rewrite at build time (Next compiles rewrites into
# the build output); the server-side API client also reads it at runtime.

# ---- deps: install exact dependencies from the lockfile ----
FROM node:22-alpine AS deps
WORKDIR /repo/apps/web
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci --no-audit --no-fund

# ---- build ----
FROM node:22-alpine AS build
WORKDIR /repo
ENV NEXT_TELEMETRY_DISABLED=1
ARG API_INTERNAL_URL=http://api:8000
ENV API_INTERNAL_URL=${API_INTERNAL_URL}
COPY packages/shared ./packages/shared
COPY apps/web ./apps/web
COPY --from=deps /repo/apps/web/node_modules ./apps/web/node_modules
WORKDIR /repo/apps/web
RUN npm run build

# ---- runtime: only the standalone server, static assets, non-root ----
FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0
ARG API_INTERNAL_URL=http://api:8000
ENV API_INTERNAL_URL=${API_INTERNAL_URL}
RUN addgroup -S -g 1001 guardhub && adduser -S -u 1001 -G guardhub -H -s /sbin/nologin guardhub
# outputFileTracingRoot is the repo root, so the server lives at apps/web/server.js.
# The i18n catalogs are statically imported, so they are bundled into the server output.
COPY --from=build --chown=guardhub:guardhub /repo/apps/web/.next/standalone ./
COPY --from=build --chown=guardhub:guardhub /repo/apps/web/.next/static ./apps/web/.next/static
# Error-tracking test event, run only via `docker compose exec web node apps/web/scripts/sentry-test.mjs`
# (resolves @sentry/node from the standalone node_modules; no HTTP route).
COPY --from=build --chown=guardhub:guardhub /repo/apps/web/scripts/sentry-test.mjs ./apps/web/scripts/sentry-test.mjs
USER guardhub
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:3000/ || exit 1
CMD ["node", "apps/web/server.js"]
