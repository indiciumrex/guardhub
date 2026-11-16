/**
 * next-intl request config (no locale URL prefixes): the locale comes from the NEXT_LOCALE
 * cookie, which middleware.ts negotiates from Accept-Language on the first visit.
 */
import { cookies } from "next/headers";
import { getRequestConfig } from "next-intl/server";
import { DEFAULT_LOCALE, isLocale, LOCALE_COOKIE } from "@/lib/i18n/config";
import { getMessages } from "@/lib/i18n/messages";

export default getRequestConfig(async () => {
  const store = await cookies();
  const cookieLocale = store.get(LOCALE_COOKIE)?.value;
  const locale = isLocale(cookieLocale) ? cookieLocale : DEFAULT_LOCALE;
  return {
    locale,
    messages: getMessages(locale),
    timeZone: "UTC",
  };
});
