"use client";
/**
 * Anonymous scan page body: live progress + report, then the "save this scan" call to action
 * (register/login → 2FA → /account/claim, which claims it with the stored token).
 */
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { hostOf, PENDING_CLAIM_KEY, type PendingClaim } from "@/lib/navigation";
import type { ScanView } from "@/lib/types";
import { ScanLive } from "./ScanLive";

function SaveScanCta({ scan }: { scan: ScanView }) {
  const t = useTranslations("scanLive");
  const router = useRouter();

  function save() {
    const pending: PendingClaim = { scanId: scan.id, name: hostOf(scan.target_url) };
    try {
      window.sessionStorage.setItem(PENDING_CLAIM_KEY, JSON.stringify(pending));
    } catch {
      // Without storage the claim page will explain what happened.
    }
    router.push("/account/claim");
  }

  return (
    <div className="w-full rounded-lg border border-teal-200 bg-teal-50 p-4 dark:border-teal-800 dark:bg-navy-950">
      <p className="text-sm text-navy-900 dark:text-slate-100">{t("saveBody")}</p>
      <button type="button" onClick={save} className="gh-btn-primary mt-3">
        {t("saveCta")}
      </button>
    </div>
  );
}

export function PublicScanView({ scanId }: { scanId: string }) {
  return (
    <ScanLive
      scanId={scanId}
      source="public"
      renderActions={(scan) => <SaveScanCta scan={scan} />}
    />
  );
}
