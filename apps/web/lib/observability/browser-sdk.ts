/**
 * The only parts of @sentry/browser we use. Lazy-loaded by browser.ts; importing names (not the
 * whole namespace) lets the bundler drop replay, feedback, tracing and profiling code.
 */
export {
  captureException,
  dedupeIntegration,
  globalHandlersIntegration,
  httpContextIntegration,
  init,
  linkedErrorsIntegration,
} from "@sentry/browser";
