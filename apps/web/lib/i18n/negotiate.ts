/**
 * Accept-Language negotiation (RFC 9110 §12.5.4) against the supported locale list.
 * Pure functions: no Next.js imports, so they run in middleware (edge) and in unit tests.
 */
import { DEFAULT_LOCALE, LOCALES, type Locale } from "./config";

export interface LanguageRange {
  tag: string;
  q: number;
}

/** Parses an Accept-Language header into ranges ordered by q (desc), keeping header order on ties. */
export function parseAcceptLanguage(header: string | null | undefined): LanguageRange[] {
  if (!header) return [];
  const ranges: (LanguageRange & { index: number })[] = [];
  header.split(",").forEach((part, index) => {
    const [rawTag, ...params] = part.trim().split(";");
    const tag = (rawTag ?? "").trim();
    if (!tag || !/^(\*|[a-zA-Z]{1,8}(-[a-zA-Z0-9]{1,8})*)$/.test(tag)) return;
    let q = 1;
    for (const param of params) {
      const [key, value] = param.trim().split("=");
      if (key?.trim().toLowerCase() === "q") {
        const parsed = Number.parseFloat((value ?? "").trim());
        q = Number.isFinite(parsed) ? Math.min(Math.max(parsed, 0), 1) : 0;
      }
    }
    if (q > 0) ranges.push({ tag, q, index });
  });
  ranges.sort((a, b) => b.q - a.q || a.index - b.index);
  return ranges.map(({ tag, q }) => ({ tag, q }));
}

/** Maps one language tag to a supported locale, or null. `zh*` → `zh-CN`, `tr-TR` → `tr`. */
export function matchLocale(tag: string): Locale | null {
  const lower = tag.toLowerCase();
  const exact = LOCALES.find((locale) => locale.toLowerCase() === lower);
  if (exact) return exact;
  const base = lower.split("-")[0];
  if (base === "zh") return "zh-CN"; // the only Chinese variant we ship (Simplified)
  return LOCALES.find((locale) => locale.toLowerCase() === base) ?? null;
}

/** Picks the best supported locale for an Accept-Language header; defaults to `en`. */
export function negotiateLocale(header: string | null | undefined): Locale {
  for (const { tag } of parseAcceptLanguage(header)) {
    if (tag === "*") return DEFAULT_LOCALE;
    const match = matchLocale(tag);
    if (match) return match;
  }
  return DEFAULT_LOCALE;
}
