"use client";
/**
 * Claims the anonymous scan saved in sessionStorage (POST /projects/claim) and opens the
 * new project. Reached after register/login → 2FA from the "save this scan" button.
 */
import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import { PENDING_CLAIM_KEY, scanTokenKey, type PendingClaim } from "@/lib/navigation";
import type { Project } from "@/lib/types";
import { useErrorMessage } from "@/lib/use-error-message";
import { Alert } from "@/components/ui/Alert";

type ClaimState = { kind: "working" } | { kind: "nothing" } | { kind: "error"; error: unknown };

function readPending(): { claim: PendingClaim; token: string } | null {
  try {
    const raw = window.sessionStorage.getItem(PENDING_CLAIM_KEY);
    if (!raw) return null;
    const claim = JSON.parse(raw) as Partial<PendingClaim>;
    if (typeof claim.scanId !== "string" || typeof claim.name !== "string") return null;
    const token = window.sessionStorage.getItem(scanTokenKey(claim.scanId));
    return token ? { claim: { scanId: claim.scanId, name: claim.name }, token } : null;
  } catch {
    return null;
  }
}

export function ClaimScan() {
  const t = useTranslations("claim");
  const tCommon = useTranslations("common");
  const router = useRouter();
  const errorMessage = useErrorMessage();
  const [state, setState] = useState<ClaimState>({ kind: "working" });
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    const pending = readPending();
    if (!pending) {
      setState({ kind: "nothing" });
      return;
    }
    apiFetch<Project>("/projects/claim", {
      method: "POST",
      body: {
        scan_id: pending.claim.scanId,
        access_token: pending.token,
        name: pending.claim.name,
      },
    })
      .then((project) => {
        try {
          window.sessionStorage.removeItem(PENDING_CLAIM_KEY);
          window.sessionStorage.removeItem(scanTokenKey(pending.claim.scanId));
        } catch {
          // ignore
        }
        router.replace(`/account/projects/${encodeURIComponent(project.id)}`);
      })
      .catch((error: unknown) => setState({ kind: "error", error }));
  }, [router]);

  if (state.kind === "working") {
    return (
      <p role="status" className="gh-muted">
        {t("working")}
      </p>
    );
  }
  if (state.kind === "nothing") {
    return (
      <div className="space-y-4">
        <Alert tone="info" label={t("nothingLabel")}>
          {t("nothing")}
        </Alert>
        <Link href="/account" className="gh-btn-secondary">
          {t("toAccount")}
        </Link>
      </div>
    );
  }
  return (
    <div className="space-y-4">
      <Alert tone="error" label={tCommon("errorLabel")}>
        {errorMessage(state.error)}
      </Alert>
      <Link href="/account" className="gh-btn-secondary">
        {t("toAccount")}
      </Link>
    </div>
  );
}
