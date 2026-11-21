"use client";
/**
 * GitHub repositories on the account page (ADR-0006): connect the GuardHub GitHub App, add the
 * repositories it may read as projects, and disconnect (uninstalls the App at GitHub).
 */
import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import type { GitHubInstallation, GitHubRepo, GitHubStatus, Project } from "@/lib/types";
import { useErrorMessage } from "@/lib/use-error-message";
import { Alert } from "@/components/ui/Alert";

function settingsUrl(installation: GitHubInstallation): string {
  return installation.account_type === "Organization"
    ? `https://github.com/organizations/${encodeURIComponent(installation.account_login)}/settings/installations`
    : "https://github.com/settings/installations";
}

function InstallationCard({ installation }: { installation: GitHubInstallation }) {
  const t = useTranslations("github");
  const tCommon = useTranslations("common");
  const router = useRouter();
  const errorMessage = useErrorMessage();
  const [repos, setRepos] = useState<GitHubRepo[] | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);

  async function loadRepos() {
    setBusy("list");
    setError(null);
    try {
      setRepos(
        await apiFetch<GitHubRepo[]>(
          `/github/installations/${encodeURIComponent(installation.id)}/repositories`,
        ),
      );
    } catch (err) {
      setError(err);
    } finally {
      setBusy(null);
    }
  }

  async function addRepo(repoId: number) {
    setBusy(`add-${repoId}`);
    setError(null);
    try {
      const project = await apiFetch<Project>(
        `/github/installations/${encodeURIComponent(installation.id)}/repositories`,
        { method: "POST", body: { repo_id: repoId } },
      );
      router.push(`/account/projects/${encodeURIComponent(project.id)}`);
    } catch (err) {
      setError(err);
      setBusy(null);
    }
  }

  async function disconnect() {
    if (!window.confirm(t("disconnectConfirm", { account: installation.account_login }))) return;
    setBusy("disconnect");
    setError(null);
    try {
      await apiFetch<void>(`/github/installations/${encodeURIComponent(installation.id)}`, {
        method: "DELETE",
      });
      router.refresh();
    } catch (err) {
      setError(err);
      setBusy(null);
    }
  }

  return (
    <li className="rounded-xl border border-slate-200 p-4 dark:border-navy-700">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="font-semibold">{t("connectedAs", { account: installation.account_login })}</p>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            className="gh-btn-secondary"
            disabled={busy !== null}
            onClick={repos ? () => setRepos(null) : loadRepos}
          >
            {busy === "list" ? tCommon("working") : repos ? t("hideRepos") : t("chooseRepos")}
          </button>
          <button
            type="button"
            className="gh-btn-secondary"
            disabled={busy !== null}
            onClick={disconnect}
          >
            {busy === "disconnect" ? tCommon("working") : t("disconnect")}
          </button>
        </div>
      </div>
      {error ? (
        <div className="mt-3">
          <Alert tone="error" label={tCommon("errorLabel")}>
            {errorMessage(error)}
          </Alert>
        </div>
      ) : null}
      {repos ? (
        repos.length === 0 ? (
          <p className="gh-muted mt-3 text-sm">{t("noRepos")}</p>
        ) : (
          <ul className="mt-3 divide-y divide-slate-200 dark:divide-navy-700">
            {repos.map((repo) => (
              <li
                key={repo.repo_id}
                className="flex flex-wrap items-center justify-between gap-2 py-2"
              >
                <span className="break-all text-sm">
                  {repo.full_name}
                  {repo.private ? (
                    <span className="gh-muted ml-2 text-xs">{t("private")}</span>
                  ) : null}
                </span>
                {repo.project_id ? (
                  <Link
                    href={`/account/projects/${encodeURIComponent(repo.project_id)}`}
                    className="gh-link text-sm"
                  >
                    {t("openProject")}
                  </Link>
                ) : (
                  <button
                    type="button"
                    className="gh-btn-primary"
                    disabled={busy !== null}
                    onClick={() => addRepo(repo.repo_id)}
                  >
                    {busy === `add-${repo.repo_id}` ? tCommon("working") : t("add")}
                  </button>
                )}
              </li>
            ))}
          </ul>
        )
      ) : null}
      <p className="mt-3 text-sm">
        <a
          href={settingsUrl(installation)}
          className="gh-link"
          target="_blank"
          rel="noopener noreferrer"
        >
          {t("manageOnGitHub")}
        </a>
      </p>
    </li>
  );
}

export function GitHubSection({ status }: { status: GitHubStatus }) {
  const t = useTranslations("github");
  const tCommon = useTranslations("common");
  const errorMessage = useErrorMessage();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function connect() {
    setBusy(true);
    setError(null);
    try {
      const { install_url } = await apiFetch<{ install_url: string }>("/github/connect", {
        method: "POST",
      });
      window.location.assign(install_url);
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <p className="gh-muted text-sm">{t("intro")}</p>
      {!status.configured ? (
        <p className="gh-muted text-sm">{t("notConfigured")}</p>
      ) : (
        <>
          {status.installations.length > 0 ? (
            <ul className="space-y-3">
              {status.installations.map((installation) => (
                <InstallationCard key={installation.id} installation={installation} />
              ))}
            </ul>
          ) : null}
          <div className="space-y-2">
            <button type="button" className="gh-btn-primary" disabled={busy} onClick={connect}>
              {busy ? tCommon("working") : t("connect")}
            </button>
            <p className="gh-muted text-xs">{t("connectHint")}</p>
          </div>
          {error ? (
            <Alert tone="error" label={tCommon("errorLabel")}>
              {errorMessage(error)}
            </Alert>
          ) : null}
        </>
      )}
    </div>
  );
}
