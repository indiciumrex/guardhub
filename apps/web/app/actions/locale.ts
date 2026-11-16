"use server";
/**
 * Server action behind the navbar language selector: stores the choice in the NEXT_LOCALE
 * cookie and, when a session cookie is present, saves it on the profile (PATCH /auth/me).
 */
import { cookies } from "next/headers";
import { ApiError } from "@/lib/api";
import { serverApiFetch } from "@/lib/api-server";
import { isLocale, LOCALE_COOKIE, localeCookieOptions } from "@/lib/i18n/config";
import type { User } from "@/lib/types";

export async function setLocaleAction(locale: string): Promise<{ ok: boolean }> {
  if (!isLocale(locale)) return { ok: false };
  const store = await cookies();
  store.set(LOCALE_COOKIE, locale, localeCookieOptions);

  if (store.has("gh_session")) {
    try {
      await serverApiFetch<User>("/auth/me", { method: "PATCH", body: { locale } });
    } catch (error) {
      // Not logged in (or pre-MFA) is fine: the cookie alone carries the preference.
      if (!(error instanceof ApiError)) throw error;
    }
  }
  return { ok: true };
}
