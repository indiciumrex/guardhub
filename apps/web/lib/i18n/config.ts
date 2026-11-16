/**
 * Supported locales (GUARDHUB_STANDARDS §7.5). Pure data; safe in edge, server and client code.
 * The locale lives in the NEXT_LOCALE cookie, never in the URL.
 */
export const LOCALES = ["en", "de", "tr", "fr", "it", "es", "zh-CN", "hi", "ru"] as const;
export type Locale = (typeof LOCALES)[number];

export const DEFAULT_LOCALE: Locale = "en";
export const LOCALE_COOKIE = "NEXT_LOCALE";
export const LOCALE_COOKIE_MAX_AGE = 60 * 60 * 24 * 365; // 1 year, in seconds

/** Language names written in their own language, shown in the language selector. */
export const NATIVE_LOCALE_NAMES: Record<Locale, string> = {
  en: "English",
  de: "Deutsch",
  tr: "Türkçe",
  fr: "Français",
  it: "Italiano",
  es: "Español",
  "zh-CN": "简体中文",
  hi: "हिन्दी",
  ru: "Русский",
};

export function isLocale(value: unknown): value is Locale {
  return typeof value === "string" && (LOCALES as readonly string[]).includes(value);
}

/** Cookie options shared by middleware and the locale server action. */
export const localeCookieOptions = {
  httpOnly: true,
  sameSite: "lax" as const,
  path: "/",
  maxAge: LOCALE_COOKIE_MAX_AGE,
  secure: process.env.NODE_ENV === "production",
};
