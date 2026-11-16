"use client";
/**
 * Navbar language dropdown (§7.5). A button + listbox following the WAI-ARIA "select-only
 * combobox" keyboard model: Enter/Space/ArrowDown open it, arrows/Home/End move, Enter selects,
 * Escape closes. Language names are shown in their own language.
 */
import { useEffect, useId, useRef, useState, useTransition, type KeyboardEvent } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { setLocaleAction } from "@/app/actions/locale";
import { LOCALES, NATIVE_LOCALE_NAMES, type Locale } from "@/lib/i18n/config";

export function LanguageSwitcher({ currentLocale }: { currentLocale: Locale }) {
  const t = useTranslations("nav");
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(() => LOCALES.indexOf(currentLocale));
  const [pending, startTransition] = useTransition();
  const baseId = useId();
  const listId = `${baseId}-list`;
  const labelId = `${baseId}-label`;
  const buttonRef = useRef<HTMLButtonElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const wrapperRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    listRef.current?.focus();
    const onPointerDown = (event: PointerEvent) => {
      if (!wrapperRef.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("pointerdown", onPointerDown);
    return () => document.removeEventListener("pointerdown", onPointerDown);
  }, [open]);

  function openList() {
    setActiveIndex(LOCALES.indexOf(currentLocale));
    setOpen(true);
  }

  function close(focusButton = true) {
    setOpen(false);
    if (focusButton) buttonRef.current?.focus();
  }

  function choose(locale: Locale) {
    close();
    if (locale === currentLocale) return;
    startTransition(async () => {
      await setLocaleAction(locale);
      router.refresh();
    });
  }

  function onButtonKeyDown(event: KeyboardEvent<HTMLButtonElement>) {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      openList();
    }
  }

  function onListKeyDown(event: KeyboardEvent<HTMLUListElement>) {
    const last = LOCALES.length - 1;
    switch (event.key) {
      case "ArrowDown":
        event.preventDefault();
        setActiveIndex((i) => Math.min(i + 1, last));
        break;
      case "ArrowUp":
        event.preventDefault();
        setActiveIndex((i) => Math.max(i - 1, 0));
        break;
      case "Home":
        event.preventDefault();
        setActiveIndex(0);
        break;
      case "End":
        event.preventDefault();
        setActiveIndex(last);
        break;
      case "Enter":
      case " ": {
        event.preventDefault();
        const locale = LOCALES[activeIndex];
        if (locale) choose(locale);
        break;
      }
      case "Escape":
        event.preventDefault();
        close();
        break;
      case "Tab":
        close(false);
        break;
      default:
        break;
    }
  }

  return (
    <div ref={wrapperRef} className="relative">
      <span id={labelId} className="sr-only">
        {t("language")}
      </span>
      <button
        ref={buttonRef}
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? listId : undefined}
        aria-labelledby={`${labelId} ${baseId}-value`}
        aria-busy={pending}
        onClick={() => (open ? close() : openList())}
        onKeyDown={onButtonKeyDown}
        className="inline-flex min-h-11 items-center gap-2 rounded-md border border-slate-300 bg-white px-3 py-2 text-sm font-medium text-navy-900 hover:bg-slate-100 dark:border-navy-700 dark:bg-navy-900 dark:text-slate-100 dark:hover:bg-navy-800"
      >
        <svg viewBox="0 0 20 20" className="h-4 w-4" aria-hidden="true" focusable="false">
          <path
            fill="currentColor"
            d="M10 2a8 8 0 1 0 0 16 8 8 0 0 0 0-16Zm5.9 7h-2.4a12.6 12.6 0 0 0-1.1-4.6A6 6 0 0 1 15.9 9ZM10 4.1c.7.9 1.4 2.6 1.5 4.9h-3c.1-2.3.8-4 1.5-4.9ZM7.6 4.4A12.6 12.6 0 0 0 6.5 9H4.1a6 6 0 0 1 3.5-4.6ZM4.1 11h2.4c.1 1.8.5 3.4 1.1 4.6A6 6 0 0 1 4.1 11Zm5.9 4.9c-.7-.9-1.4-2.6-1.5-4.9h3c-.1 2.3-.8 4-1.5 4.9Zm2.4-.3c.6-1.2 1-2.8 1.1-4.6h2.4a6 6 0 0 1-3.5 4.6Z"
          />
        </svg>
        <span id={`${baseId}-value`} lang={currentLocale}>
          {NATIVE_LOCALE_NAMES[currentLocale]}
        </span>
        <svg viewBox="0 0 20 20" className="h-4 w-4" aria-hidden="true" focusable="false">
          <path
            fill="currentColor"
            d="M5.3 7.3a1 1 0 0 1 1.4 0L10 10.6l3.3-3.3a1 1 0 1 1 1.4 1.4l-4 4a1 1 0 0 1-1.4 0l-4-4a1 1 0 0 1 0-1.4Z"
          />
        </svg>
      </button>
      {open ? (
        <ul
          ref={listRef}
          id={listId}
          role="listbox"
          tabIndex={-1}
          aria-labelledby={labelId}
          aria-activedescendant={`${baseId}-opt-${activeIndex}`}
          onKeyDown={onListKeyDown}
          className="absolute right-0 z-40 mt-2 max-h-80 w-48 overflow-auto rounded-lg border border-slate-200 bg-white py-1 shadow-lg dark:border-navy-700 dark:bg-navy-900"
        >
          {LOCALES.map((locale, index) => {
            const selected = locale === currentLocale;
            const active = index === activeIndex;
            return (
              <li
                key={locale}
                id={`${baseId}-opt-${index}`}
                role="option"
                aria-selected={selected}
                lang={locale}
                onClick={() => choose(locale)}
                onMouseEnter={() => setActiveIndex(index)}
                className={`flex cursor-pointer items-center justify-between px-3 py-2 text-sm ${
                  active
                    ? "bg-teal-50 text-navy-950 dark:bg-navy-700 dark:text-white"
                    : "text-navy-900 dark:text-slate-100"
                }`}
              >
                <span>{NATIVE_LOCALE_NAMES[locale]}</span>
                {selected ? (
                  <svg viewBox="0 0 20 20" className="h-4 w-4" aria-hidden="true" focusable="false">
                    <path
                      fill="currentColor"
                      d="M7.7 13.3 4.4 10a1 1 0 1 0-1.4 1.4l4 4a1 1 0 0 0 1.4 0l9-9A1 1 0 1 0 16 5Z"
                    />
                  </svg>
                ) : null}
              </li>
            );
          })}
        </ul>
      ) : null}
    </div>
  );
}
