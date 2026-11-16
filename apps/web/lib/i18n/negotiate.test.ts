import { describe, expect, it } from "vitest";
import { matchLocale, negotiateLocale, parseAcceptLanguage } from "./negotiate";

describe("parseAcceptLanguage", () => {
  it("orders by q-value and keeps header order on ties", () => {
    expect(parseAcceptLanguage("fr;q=0.5, de, en;q=0.8, it")).toEqual([
      { tag: "de", q: 1 },
      { tag: "it", q: 1 },
      { tag: "en", q: 0.8 },
      { tag: "fr", q: 0.5 },
    ]);
  });

  it("drops q=0, malformed tags and empty input", () => {
    expect(parseAcceptLanguage("tr;q=0, ;;, en")).toEqual([{ tag: "en", q: 1 }]);
    expect(parseAcceptLanguage("")).toEqual([]);
    expect(parseAcceptLanguage(null)).toEqual([]);
  });

  it("treats an invalid q as 0", () => {
    expect(parseAcceptLanguage("de;q=abc, es")).toEqual([{ tag: "es", q: 1 }]);
  });
});

describe("matchLocale", () => {
  it("matches exact tags case-insensitively", () => {
    expect(matchLocale("zh-cn")).toBe("zh-CN");
    expect(matchLocale("EN")).toBe("en");
  });

  it("falls back to the base language", () => {
    expect(matchLocale("tr-TR")).toBe("tr");
    expect(matchLocale("de-AT")).toBe("de");
    expect(matchLocale("pt-BR")).toBeNull();
  });

  it("maps every Chinese tag to zh-CN", () => {
    expect(matchLocale("zh")).toBe("zh-CN");
    expect(matchLocale("zh-Hans-CN")).toBe("zh-CN");
  });
});

describe("negotiateLocale", () => {
  it("returns the best supported language", () => {
    expect(negotiateLocale("tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7")).toBe("tr");
    expect(negotiateLocale("pt-BR, ru;q=0.6, en;q=0.4")).toBe("ru");
    expect(negotiateLocale("zh,en;q=0.5")).toBe("zh-CN");
    expect(negotiateLocale("en;q=0.2, hi;q=0.9")).toBe("hi");
  });

  it("defaults to en", () => {
    expect(negotiateLocale(undefined)).toBe("en");
    expect(negotiateLocale("pt-BR, ja")).toBe("en");
    expect(negotiateLocale("*")).toBe("en");
  });
});
