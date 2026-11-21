/**
 * TypeScript shapes of the public HTTP API payloads (docs/architecture.md §4 and the Phase 1
 * contracts in §8.2–§8.4: schedule, scan diff, score trend, alerts).
 * Finding primitives (Severity, Evidence) come from the generated contract.
 */
import type { Evidence, Severity } from "./contract.gen";

export type { Severity } from "./contract.gen";

export type ScanStatus = "queued" | "running" | "done" | "failed";
export type CheckRunStatus = ScanStatus;
export type FindingStatus = "open" | "fixed" | "ignored";
export type Role = "user" | "admin";
export type MfaState = "setup_required" | "required";
export type HealthState = "ok" | "degraded" | "down";

export type SeverityCounts = Record<Severity, number>;

export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
}

// §4.1
export interface HealthResponse {
  status: HealthState;
  components: Record<string, string>;
}

export interface CheckInfo {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
}

// §4.2
export interface OwnershipInstructions {
  well_known_url: string;
  meta_tag: string;
  dns_name: string;
  dns_value: string;
}

export interface Challenge {
  challenge_id: string;
  target_origin: string;
  token: string;
  expires_at: string;
  instructions: OwnershipInstructions;
}

export interface ChallengeScanResponse {
  scan_id: string;
  access_token: string;
}

// §4.3
export interface User {
  id: string;
  email: string;
  role: Role;
  locale: string;
  totp_enabled: boolean;
  mfa_complete: boolean;
  created_at: string;
}

export interface RegisterResponse {
  user: User;
  mfa: MfaState;
}

export interface LoginResponse {
  mfa: MfaState;
}

export interface TotpSetupResponse {
  secret: string;
  otpauth_uri: string;
}

export interface VerifyTotpResponse {
  user: User;
}

// §4.4 (+ §8.2/§8.3 fields)
export type ScanTrigger = "manual" | "scheduled" | "ci";
export type ScanFrequency = "off" | "daily" | "weekly";
export type SchedulePausedReason = "ownership_lost";

export interface ScanSummary {
  id: string;
  project_id: string | null;
  target_url: string;
  status: ScanStatus;
  score: number | null;
  finding_counts: SeverityCounts;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  trigger: ScanTrigger;
  /** Check ids that could not run in this scan (never compared in a diff). */
  failed_checks: string[];
}

export interface ProgressItem {
  check_id: string;
  name: string;
  status: CheckRunStatus;
}

export interface FindingView {
  id: string;
  check_id: string;
  finding_key: string;
  severity: Severity;
  title: string;
  summary: string;
  why: string;
  fix: string;
  evidence: Evidence;
  status: FindingStatus;
}

export interface ScanView extends ScanSummary {
  progress: ProgressItem[];
  findings: FindingView[];
}

export interface ProjectVerification extends OwnershipInstructions {
  token: string;
}

export type ProjectKind = "site" | "repo";

export interface Project {
  id: string;
  name: string;
  /** "repo": a GitHub repository connected through the GitHub App (ADR-0006). */
  kind: ProjectKind;
  repo_full_name: string | null;
  target_url: string;
  verified: boolean;
  ownership_verified_at: string | null;
  verification: ProjectVerification;
  last_scan: ScanSummary | null;
  created_at: string;
  scan_frequency: ScanFrequency;
  next_scan_at: string | null;
  schedule_paused_reason: SchedulePausedReason | null;
}

// §8.3 scan diff and trend
export interface DiffItem {
  fingerprint: string;
  check_id: string;
  finding_key: string;
  severity: Severity;
  title: string;
  summary: string;
}

export interface ScanDiff {
  scan_id: string;
  /** null when this is the project's first finished scan (the baseline). */
  base_scan_id: string | null;
  project_id: string;
  score: number;
  base_score: number | null;
  score_delta: number | null;
  compared_checks: string[];
  /** Checks that could not run in one of the two scans, so they were not compared. */
  skipped_checks: string[];
  new: DiffItem[];
  regressed: DiffItem[];
  fixed: DiffItem[];
  unchanged_count: number;
}

export interface TrendPoint {
  scan_id: string;
  finished_at: string;
  score: number;
  trigger: ScanTrigger;
}

// §8.4 alerts
export type NotificationChannel = "email" | "slack";
export type NotificationStatus = "pending" | "sent" | "failed" | "skipped";

export interface NotificationSettings {
  email_enabled: boolean;
  notify_new: boolean;
  notify_regression: boolean;
  notify_fixed: boolean;
  slack_configured: boolean;
  email: string;
}

/** PUT body. `slack_webhook_url`: omitted = keep the stored one, null = remove it. */
export interface NotificationSettingsUpdate {
  email_enabled: boolean;
  notify_new: boolean;
  notify_regression: boolean;
  notify_fixed: boolean;
  slack_webhook_url?: string | null;
}

/** What an alert was about. Only "scan_change" has a scan and change counts. */
export type NotificationKind = "scan_change" | "monitoring_paused" | "test";

/** GET /account/notifications/history?show=… (the API's default is "alerts"). */
export type NotificationHistoryFilter = "alerts" | "test" | "all";

export interface NotificationHistoryItem {
  id: string;
  kind: NotificationKind;
  scan_id: string | null;
  project_id: string | null;
  channel: NotificationChannel;
  status: NotificationStatus;
  new_count: number;
  regression_count: number;
  fixed_count: number;
  created_at: string;
  sent_at: string | null;
}

/** Same rule the API enforces (§8.4); the server stays authoritative. */
export const SLACK_WEBHOOK_PATTERN =
  /^https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_/-]{10,200}$/;

export function isSlackWebhookUrl(value: string): boolean {
  return SLACK_WEBHOOK_PATTERN.test(value);
}

// §4.5
export interface AdminModule {
  key: string;
  name: string;
  category: string;
  enabled_global: boolean;
  min_plan: "free" | "pro" | "agency";
}

export interface HealthCheck {
  module_key: string;
  status: HealthState;
  error_rate: number | null;
  latency_ms: number | null;
  checked_at: string;
}

export interface AiStatus {
  provider: string | null;
  enabled: boolean;
  active: boolean;
}

// §8.5 (ADR-0003): admin trusted domains
export type TrustedDomainStatus = "pending" | "active" | "suspended" | "revoked";
export type OwnershipMethod = "well_known" | "meta_tag" | "dns_txt";

export interface TrustedDomain {
  id: string;
  host: string;
  target_origin: string;
  status: TrustedDomainStatus;
  verification: ProjectVerification;
  method: OwnershipMethod | null;
  verified_at: string | null;
  last_checked_at: string | null;
  suspended_at: string | null;
  created_at: string;
}

/** Admin list endpoints take limit/offset; accept either a bare array or a page envelope. */
export type ListPayload<T> = T[] | { items: T[]; total?: number };

export function listItems<T>(payload: ListPayload<T> | null | undefined): T[] {
  if (!payload) return [];
  return Array.isArray(payload) ? payload : payload.items;
}

export function isScanActive(status: ScanStatus): boolean {
  return status === "queued" || status === "running";
}

// GitHub repository scanning (ADR-0006)
export interface GitHubInstallation {
  id: string;
  account_login: string;
  account_type: "User" | "Organization";
  created_at: string;
}

export interface GitHubStatus {
  configured: boolean;
  installations: GitHubInstallation[];
}

export interface GitHubRepo {
  repo_id: number;
  full_name: string;
  private: boolean;
  project_id: string | null;
}
