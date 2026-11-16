import { describe, expect, it } from "vitest";
import trCatalog from "@shared/i18n/tr/ui.json";
import { deepMerge, enMessages, getMessages, type MessageTree } from "./messages";

function flattenKeys(tree: MessageTree, prefix = ""): string[] {
  return Object.entries(tree).flatMap(([key, value]) =>
    typeof value === "string" ? [`${prefix}${key}`] : flattenKeys(value, `${prefix}${key}.`),
  );
}

describe("deepMerge", () => {
  it("overrides leaves and keeps missing keys from the base", () => {
    const base = { a: "A", nested: { b: "B", c: "C" } };
    const override = { nested: { b: "B2" } };
    expect(deepMerge(base, override)).toEqual({ a: "A", nested: { b: "B2", c: "C" } });
  });

  it("ignores empty strings so they fall back to English", () => {
    expect(deepMerge({ a: "A" }, { a: "" })).toEqual({ a: "A" });
  });

  it("does not mutate the base tree", () => {
    const base = { nested: { b: "B" } };
    deepMerge(base, { nested: { b: "X" } });
    expect(base.nested.b).toBe("B");
  });
});

describe("getMessages", () => {
  it("falls back to English for an empty catalog", () => {
    expect(getMessages("de")).toEqual(enMessages);
  });

  it("uses Turkish where available", () => {
    const tr = getMessages("tr");
    expect((tr.nav as MessageTree).scan).toBe("Ücretsiz tarama");
  });

  it("has a complete Turkish catalog (every en key is translated)", () => {
    const enKeys = flattenKeys(enMessages).sort();
    expect(flattenKeys(trCatalog as MessageTree).sort()).toEqual(enKeys);
  });
});
