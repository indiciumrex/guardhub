/**
 * Admin control centre payloads (apps/api/guardhub_api/admin/center.py, GUARDHUB_STANDARDS §8.3).
 * Admin-only: the API answers 404 to everyone else.
 */
import type { HealthCheck, HealthResponse, Severity } from "./types";

export type Lifecycle = "queued" | "running" | "completed" | "failed" | "timed_out" | "cancelled";
export const LIFECYCLES: Lifecycle[] = [
  "queued",
  "running",
  "completed",
  "failed",
  "timed_out",
  "cancelled",
];

export type TriageStatus = "new" | "verified" | "accepted" | "false_positive" | "resolved";
export const TRIAGE_STATUSES: TriageStatus[] = [
  "new",
  "verified",
  "accepted",
  "false_positive",
  "resolved",
];

export type ModuleStatus = "active" | "maintenance" | "disabled";
export type Plan = "free" | "pro" | "agency";
export const PLANS: Plan[] = ["free", "pro", "agency"];

export interface ScanCounts {
  total: number;
  queued: number;
  running: number;
  completed: number;
  failed: number;
  timed_out: number;
  cancelled: number;
  last_24h: number;
}

export type SeverityTotals = Record<Severity, number> & { total: number };

export interface ModuleRate {
  check_id: string;
  runs: number;
  failed: number;
  success_rate: number | null;
}

export interface QueueView {
  available: boolean;
  stream_length: number | null;
  lag: number | null;
  pending: number | null;
  consumers: number | null;
  busiest_idle_ms: number | null;
}

export interface ScannerInfo {
  consumer: string;
  version: string;
  started_at: string;
  workers: number;
  check_concurrency: number;
  host_rps: number;
  host_burst: number;
  max_requests_per_scan: number;
  request_timeout_ms: number;
  active_enabled: boolean;
  active_oob: boolean;
  repo_scans: boolean;
}

export interface AuditDetail {
  id: number;
  actor: string;
  actor_email: string | null;
  action: string;
  target: string;
  at: string;
  changes: Record<string, string>;
  ip_hash: string | null;
}

export interface ErrorItem {
  source: "scan" | "module" | "sentry";
  at: string | null;
  title: string;
  detail: string;
  count: number | null;
  link: string | null;
}

export interface SentryView {
  configured: boolean;
  issues: ErrorItem[];
  error: string | null;
}

export interface Overview {
  scans: ScanCounts;
  findings: SeverityTotals;
  modules: ModuleRate[];
  health: HealthResponse;
  queue: QueueView;
  scanners: ScannerInfo[];
  recent_audit: AuditDetail[];
  recent_errors: ErrorItem[];
  sentry: SentryView;
}

export interface GateView {
  gate: "L" | "M";
  measured: boolean;
  meets_gate: boolean;
  source: string;
  precision: number | null;
  recall: number | null;
  false_positive_rate: number | null;
  tp: number;
  fp: number;
  fn: number;
  targets: number;
}

export interface CenterModule {
  key: string;
  name: string;
  category: string;
  enabled_global: boolean;
  min_plan: Plan;
  maintenance: boolean;
  status: ModuleStatus;
  stage: "ga" | "beta";
  is_check: boolean;
  gate: GateView | null;
  enable_blocked: string | null;
}

export interface TriageStats {
  groups: number;
  verified: number;
  accepted: number;
  false_positive: number;
  resolved: number;
  false_positive_rate: number | null;
}

export interface ModuleStats {
  check_id: string;
  runs_7d: number;
  failed_7d: number;
  success_rate_7d: number | null;
  triage: TriageStats;
}

export interface OwnershipProof {
  kind: "project" | "one_time" | "none";
  method: string | null;
  verified_at: string | null;
}

export interface AdminScan {
  id: string;
  target_url: string;
  lifecycle: Lifecycle;
  status: string;
  error: string | null;
  trigger: string;
  kind: "site" | "repo";
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  duration_seconds: number | null;
  checks: number;
  failed_checks: string[];
  score: number | null;
  project_id: string | null;
  project_name: string | null;
  owner_email: string | null;
  ownership: OwnershipProof;
  can_cancel: boolean;
  can_rerun: boolean;
}

export interface ActiveTestingState {
  approved: boolean;
  scanner_switch: "on" | "off" | "unknown";
  global_kill: boolean;
  modules_on: string[];
  oob_configured: boolean;
  effective: "on" | "off";
}

export interface Orchestration {
  counts: ScanCounts;
  queue: QueueView;
  scanners: ScannerInfo[];
  passive_limits: Record<string, number> | null;
  active_limits: Record<string, number>;
  active: ActiveTestingState;
}

export interface Classification {
  cwe: string[];
  cvss_vector: string | null;
  cvss_score: number | null;
  cves: string[];
  advisories: string[];
}

export interface FindingGroup {
  fingerprint: string;
  check_id: string;
  finding_key: string;
  severity: Severity;
  title: string;
  target_url: string;
  location: string | null;
  occurrences: number;
  first_seen: string;
  last_seen: string;
  latest_scan_id: string;
  latest_status: string;
  triage: TriageStatus;
  triage_note: string;
  triage_updated_at: string | null;
  classification: Classification;
  score_points: number;
}

export interface RiskContribution {
  severity: Severity;
  count: number;
  weight: number;
  points: number;
}

export interface RiskView {
  scan_id: string;
  target_url: string;
  score: number | null;
  recomputed: number;
  formula: string;
  weights: Record<string, number>;
  contributions: RiskContribution[];
  findings: {
    check_id: string;
    finding_key: string;
    severity: Severity;
    title: string;
    points: number;
    cwe: string[];
  }[];
  capped_at_zero: boolean;
}

export interface Monitoring {
  health: HealthResponse;
  components: HealthCheck[];
  queue: QueueView;
  scanners: ScannerInfo[];
  recent_errors: ErrorItem[];
  sentry: SentryView;
}

export interface KillState {
  scope: string;
  engaged: boolean;
}

/** GET /admin/active/owner-scan: what still blocks an owner-target active scan (ADR-0008 §8). */
export type OwnerScanLock =
  "approval" | "modules" | "kill_switch" | "scanner_switch" | "target" | "origin_busy";

export interface OwnerScanReadiness {
  approved: boolean;
  modules_on: string[];
  oob_configured: boolean;
  kill_engaged: boolean;
  scanner_switch: "on" | "off" | "unknown";
  targets: { id: string; host: string; origin: string }[];
  blocked_by: OwnerScanLock[];
}

export interface OwnerScanStarted {
  scan_id: string;
  consent_id: string;
  origin: string;
  checks: string[];
  exclude: string[];
  idor_accounts: boolean;
}

// ---- configuration & feature flags (GET /admin/config, Prompt 2 §1) ----

export type SettingValue = number | boolean | string;

export interface ConfigSetting {
  key: string;
  group: "maintenance" | "flags" | "scans" | "concurrency" | "rate_limits";
  kind: "int" | "bool" | "text";
  value: SettingValue;
  default: SettingValue;
  overridden: boolean;
  minimum: number | null;
  maximum: number | null;
  max_length: number | null;
  updated_at: string | null;
  updated_by: string | null;
}

export interface ConfigEnv {
  name: string;
  kind: "value" | "secret" | "hidden";
  configured: boolean;
  value: string | null;
}

export interface ConfigChange {
  id: number;
  at: string;
  action: "config.changed" | "config.reset" | "config.reverted";
  actor: string;
  actor_email: string | null;
  key: string;
  old: string;
  new: string;
  reason: string;
  revertible: boolean;
}

export interface ConfigView {
  settings: ConfigSetting[];
  environment: ConfigEnv[];
  history: ConfigChange[];
  cache_seconds: number;
}

// ---- operational alerts (GET /admin/alerts, Prompt 2 §2) ----

export type OpsAlertKind = "critical_finding" | "scan_failures" | "worker_offline" | "api_errors";

export interface OpsAlertRule {
  kind: OpsAlertKind;
  enabled: boolean;
  threshold: number;
  window_minutes: number;
  email: boolean;
  muted_until: string | null;
  escalate_after_minutes: number | null;
  updated_at: string;
}

export interface OpsAlert {
  id: string;
  kind: OpsAlertKind;
  status: "open" | "acknowledged" | "resolved";
  value: number;
  threshold: number;
  opened_at: string;
  last_seen_at: string;
  acknowledged_at: string | null;
  resolved_at: string | null;
  resolved_automatically: boolean;
  emailed_at: string | null;
  escalated_at: string | null;
  email_error: string | null;
}

export interface OpsAlertsView {
  open: OpsAlert[];
  recent: OpsAlert[];
  rules: OpsAlertRule[];
  email_configured: boolean;
  admin_recipients: number;
}

// ---- reports (GET /admin/reports/{kind}, Prompt 2 §3) ----

export const REPORT_KINDS = [
  "platform",
  "modules",
  "scans",
  "findings",
  "customers",
  "risk_trend",
] as const;
export type ReportKind = (typeof REPORT_KINDS)[number];
export const REPORT_DAYS = [7, 30, 90] as const;

export interface ReportView {
  kind: ReportKind;
  days: number;
  columns: string[];
  rows: (string | number | null)[][];
  total_rows: number;
  truncated: boolean;
  masked: boolean;
  generated_at: string;
}

export interface ReportSchedule {
  frequency: "weekly" | "monthly";
  enabled: boolean;
  last_sent_at: string | null;
  updated_at: string;
}

// ---- integrations (Prompt 2 §4) ----

export const API_KEY_SCOPES = ["projects:read", "scans:read", "scans:trigger"] as const;
export type ApiKeyScope = (typeof API_KEY_SCOPES)[number];
export const API_KEY_DAYS = [30, 90, 180, 365] as const;

export interface ApiKeyView {
  id: string;
  name: string;
  prefix: string;
  owner_email: string | null;
  scopes: ApiKeyScope[];
  created_at: string;
  expires_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
  status: "active" | "expired" | "revoked";
}

export interface CreatedApiKey {
  key: ApiKeyView;
  secret: string;
}

export interface EndpointTraffic {
  endpoint: string;
  requests: number;
  client_errors: number;
  server_errors: number;
  rate_limited: number;
  error_rate: number;
  avg_ms: number;
  p95_ms: number | null;
}

export const WEBHOOK_EVENTS = ["scan.completed", "ops_alert.opened", "ping"] as const;
export type WebhookEvent = (typeof WEBHOOK_EVENTS)[number];

export interface WebhookDeliveryView {
  id: string;
  event: string;
  status: "pending" | "sent" | "failed";
  attempts: number;
  http_status: number | null;
  error: string | null;
  created_at: string;
  delivered_at: string | null;
}

export interface WebhookView {
  id: string;
  name: string;
  url: string;
  events: WebhookEvent[];
  enabled: boolean;
  created_at: string;
  deliveries: WebhookDeliveryView[];
}

export interface CreatedWebhook {
  webhook: WebhookView;
  secret: string;
}
