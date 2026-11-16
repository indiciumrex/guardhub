"use client";
/**
 * Maps an API error `code` to localised text (`errors.<code>`), with a generic fallback.
 * Developer messages from the API are never shown to users.
 */
import { useTranslations } from "next-intl";
import { ApiError } from "./api";

export function useErrorMessage(): (error: unknown) => string {
  const t = useTranslations("errors");
  return (error: unknown) => {
    if (error instanceof ApiError) {
      if (error.code === "ownership_not_verified") {
        const reason = error.details?.reason;
        if (typeof reason === "string" && t.has(`verifyReason.${reason}`)) {
          return `${t("ownership_not_verified")} ${t(`verifyReason.${reason}`)}`;
        }
      }
      if (error.code === "invalid_target_url") {
        const reason = error.details?.reason;
        if (typeof reason === "string" && t.has(`targetReason.${reason}`)) {
          return `${t("invalid_target_url")} ${t(`targetReason.${reason}`)}`;
        }
      }
      if (t.has(error.code)) return t(error.code);
    }
    return t("generic");
  };
}
