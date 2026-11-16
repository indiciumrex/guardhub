/**
 * TypeScript shapes of the public HTTP API payloads (docs/architecture.md §4).
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

// §4.4
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

export interface Project {
  id: string;
  name: string;
  target_url: string;
  verified: boolean;
  ownership_verified_at: string | null;
  verification: ProjectVerification;
  last_scan: ScanSummary | null;
  created_at: string;
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
