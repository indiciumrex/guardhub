/**
 * Server-side session guards for protected routes. They ask the API (`GET /auth/me`, cookie
 * forwarded) and redirect to login / 2FA, or 404 for admin pages, as needed.
 */
import "server-only";
import { headers } from "next/headers";
import { notFound, redirect } from "next/navigation";
import { ApiError } from "./api";
import { serverApiFetch } from "./api-server";
import { loginUrl, twoFactorUrl } from "./navigation";
import type { User } from "./types";

/** The path of the current request (set by middleware), used for post-login redirects. */
export async function currentPath(): Promise<string> {
  return (await headers()).get("x-guardhub-pathname") ?? "/account";
}

/** Returns the session user, or null when there is no (valid) session. Other errors propagate. */
export async function getSessionUser(): Promise<User | null> {
  try {
    return await serverApiFetch<User>("/auth/me");
  } catch (error) {
    if (error instanceof ApiError && (error.status === 401 || error.status === 403)) return null;
    throw error;
  }
}

/** Requires a full (MFA-complete) session; otherwise redirects to login or 2FA. */
export async function requireUser(): Promise<User> {
  const user = await getSessionUser();
  const path = await currentPath();
  if (!user) redirect(loginUrl(path));
  if (!user.mfa_complete) redirect(twoFactorUrl(path));
  return user;
}

/** Requires role admin AND a full MFA session. Everyone else gets a 404 (admin stays hidden). */
export async function requireAdmin(): Promise<User> {
  const user = await getSessionUser();
  if (!user || user.role !== "admin") notFound();
  if (!user.mfa_complete) redirect(twoFactorUrl(await currentPath()));
  return user;
}

/**
 * Loads protected data and maps auth errors to navigation:
 * 401 → login, 403 (MFA) → 2FA, 404 → not-found. Anything else propagates to error.tsx.
 */
export async function loadProtected<T>(load: () => Promise<T>): Promise<T> {
  try {
    return await load();
  } catch (error) {
    if (error instanceof ApiError) {
      const path = await currentPath();
      if (error.status === 401) redirect(loginUrl(path));
      if (error.status === 403 && error.code.startsWith("mfa")) redirect(twoFactorUrl(path));
      if (error.status === 404) notFound();
    }
    throw error;
  }
}
