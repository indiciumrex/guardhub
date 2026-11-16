"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";

export function LogoutButton() {
  const t = useTranslations("account");
  const router = useRouter();
  const [busy, setBusy] = useState(false);

  async function logout() {
    setBusy(true);
    try {
      await apiFetch<void>("/auth/logout", { method: "POST" });
    } catch {
      // Even if the call fails we leave the protected area; the cookie expires anyway.
    }
    router.replace("/");
    router.refresh();
  }

  return (
    <button
      type="button"
      onClick={logout}
      disabled={busy}
      className="gh-btn-secondary min-h-9 py-1"
    >
      {t("logout")}
    </button>
  );
}
