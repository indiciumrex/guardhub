"use client";
/**
 * Live scan view. Polls the scan every ~1.5 s while it's queued/running, shows the per-check
 * progress, then the report (or the failure reason).
 * - source "public": anonymous scan; the access token is read from sessionStorage
 *   (keyed by scan id) and sent as X-Scan-Token. It is never put in the URL.
 * - source "account": the session cookie authorises the request.
 */
import { useEffect, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { useLocale, useTranslations } from "next-intl";
import { ApiError, apiFetch, SCAN_TOKEN_HEADER } from "@/lib/api";
import { scanTokenKey, hostOf } from "@/lib/navigation";
import { isScanActive, type ScanView } from "@/lib/types";
import { useErrorMessage } from "@/lib/use-error-message";
import { Alert } from "@/components/ui/Alert";
import { ObservationalBadge, ObservationalNotice } from "./ObservationalNotice";
import { ProgressList } from "./ProgressList";
import { ScanReport } from "./ScanReport";

export const POLL_INTERVAL_MS = 1500;
const MAX_CONSECUTIVE_FAILURES = 5;

type LiveState =
  | { kind: "loading" }
  | { kind: "missing_token" }
  | { kind: "ready"; scan: ScanView }
  | { kind: "error"; error: unknown };

interface ScanLiveProps {
  scanId: string;
  source: "public" | "account";
  initial?: ScanView;
  /** Extra actions under the report (e.g. "save this scan"), given the finished scan. */
  renderActions?: (scan: ScanView) => ReactNode;
}

function readToken(scanId: string): string | null {
  try {
    return window.sessionStorage.getItem(scanTokenKey(scanId));
  } catch {
    return null;
  }
}

export function ScanLive({ scanId, source, initial, renderActions }: ScanLiveProps) {
  const t = useTranslations("scanLive");
  const tCommon = useTranslations("common");
  const errorMessage = useErrorMessage();
  const locale = useLocale();
  const router = useRouter();
  const [state, setState] = useState<LiveState>(
    initial ? { kind: "ready", scan: initial } : { kind: "loading" },
  );
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;
    let failures = 0;
    let sawActive = false;
    const controller = new AbortController();

    const headers: Record<string, string> = {};
    if (source === "public") {
      const token = readToken(scanId);
      if (!token) {
        setState({ kind: "missing_token" });
        return;
      }
      headers[SCAN_TOKEN_HEADER] = token;
    }
    const path =
      source === "public"
        ? `/public/scans/${encodeURIComponent(scanId)}`
        : `/scans/${encodeURIComponent(scanId)}`;

    async function poll() {
      try {
        const scan = await apiFetch<ScanView>(path, {
          query: { locale },
          headers,
          signal: controller.signal,
        });
        if (cancelled) return;
        failures = 0;
        setState({ kind: "ready", scan });
        if (isScanActive(scan.status)) {
          sawActive = true;
          timer = window.setTimeout(poll, POLL_INTERVAL_MS);
        } else if (sawActive && source === "account") {
          // The scan just finished: drop cached server pages (project history, account list)
          // so navigating back never shows a stale score or a still-running scan.
          router.refresh();
        }
      } catch (error) {
        if (cancelled) return;
        const transient =
          error instanceof ApiError &&
          (error.status === 0 || error.status >= 500 || error.status === 429);
        failures += 1;
        if (transient && failures < MAX_CONSECUTIVE_FAILURES) {
          timer = window.setTimeout(poll, POLL_INTERVAL_MS * (failures + 1));
        } else {
          setState({ kind: "error", error });
        }
      }
    }

    // A finished server-rendered scan needs no polling. After a language switch the server
    // re-renders and passes a fresh `initial` in the new locale.
    if (initial && !isScanActive(initial.status) && attempt === 0) {
      setState({ kind: "ready", scan: initial });
      return;
    }
    void poll();

    return () => {
      cancelled = true;
      controller.abort();
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [scanId, source, locale, attempt, initial, router]);

  if (state.kind === "loading") {
    return (
      <p role="status" className="gh-muted">
        {tCommon("loading")}
      </p>
    );
  }

  if (state.kind === "missing_token") {
    return (
      <Alert tone="info" label={t("noAccessLabel")}>
        {t("noAccess")}
      </Alert>
    );
  }

  if (state.kind === "error") {
    return (
      <div className="space-y-4">
        <Alert tone="error" label={tCommon("errorLabel")}>
          {errorMessage(state.error)}
        </Alert>
        <button type="button" className="gh-btn-secondary" onClick={() => setAttempt((n) => n + 1)}>
          {tCommon("retry")}
        </button>
      </div>
    );
  }

  const { scan } = state;
  return (
    <div className="space-y-8">
      <header>
        <p className="text-sm font-semibold uppercase tracking-wide text-teal-800 dark:text-teal-300">
          {t(`statusHeading.${scan.status}`)}
        </p>
        <h1 className="mt-1 break-words text-3xl font-bold">{hostOf(scan.target_url)}</h1>
        {scan.trigger === "observe" ? (
          <p className="mt-2">
            <ObservationalBadge />
          </p>
        ) : null}
      </header>

      {scan.trigger === "observe" ? <ObservationalNotice /> : null}

      {isScanActive(scan.status) ? (
        <>
          <p className="gh-muted">{t("runningIntro")}</p>
          <ProgressList items={scan.progress} />
        </>
      ) : null}

      {scan.status === "failed" || scan.status === "cancelled" ? (
        <>
          <Alert tone="error" label={t("failedLabel")}>
            {scan.status === "cancelled"
              ? t("failureReason.cancelled")
              : t.has(`failureReason.${scan.error ?? "internal"}`)
                ? t(`failureReason.${scan.error ?? "internal"}`)
                : t("failureReason.internal")}
          </Alert>
          {scan.progress.length > 0 ? <ProgressList items={scan.progress} /> : null}
        </>
      ) : null}

      {scan.status === "done" ? <ScanReport scan={scan} actions={renderActions?.(scan)} /> : null}
    </div>
  );
}
