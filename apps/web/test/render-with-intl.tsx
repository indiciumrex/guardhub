import type { ReactElement } from "react";
import { render } from "@testing-library/react";
import { NextIntlClientProvider } from "next-intl";
import { getMessages } from "@/lib/i18n/messages";
import type { Locale } from "@/lib/i18n/config";

/** Renders a component with the real (merged) catalog for a locale. */
export function renderWithIntl(ui: ReactElement, locale: Locale = "en") {
  return render(
    <NextIntlClientProvider locale={locale} messages={getMessages(locale)} timeZone="UTC">
      {ui}
    </NextIntlClientProvider>,
  );
}
