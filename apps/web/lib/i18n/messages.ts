/**
 * UI message catalogs from packages/shared/i18n/<locale>/ui.json, statically imported so they
 * are bundled into the standalone build. Each locale is deep-merged over `en`, so any missing
 * key falls back to English (§7.5).
 */
import en from "@shared/i18n/en/ui.json";
import de from "@shared/i18n/de/ui.json";
import tr from "@shared/i18n/tr/ui.json";
import fr from "@shared/i18n/fr/ui.json";
import it from "@shared/i18n/it/ui.json";
import es from "@shared/i18n/es/ui.json";
import zhCN from "@shared/i18n/zh-CN/ui.json";
import hi from "@shared/i18n/hi/ui.json";
import ru from "@shared/i18n/ru/ui.json";
import type { Locale } from "./config";

export interface MessageTree {
  [key: string]: string | MessageTree;
}

export const enMessages: MessageTree = en;

const catalogs: Record<Locale, MessageTree> = {
  en,
  de,
  tr,
  fr,
  it,
  es,
  "zh-CN": zhCN,
  hi,
  ru,
};

function isTree(value: unknown): value is MessageTree {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Returns a new tree: `override` values win, everything else comes from `base`. */
export function deepMerge(base: MessageTree, override: MessageTree): MessageTree {
  const result: MessageTree = { ...base };
  for (const [key, value] of Object.entries(override)) {
    const baseValue = result[key];
    if (isTree(value) && isTree(baseValue)) {
      result[key] = deepMerge(baseValue, value);
    } else if (typeof value === "string" && value.length > 0) {
      result[key] = value;
    } else if (isTree(value) && baseValue === undefined) {
      result[key] = value;
    }
  }
  return result;
}

export function getMessages(locale: Locale): MessageTree {
  if (locale === "en") return catalogs.en;
  return deepMerge(catalogs.en, catalogs[locale]);
}
