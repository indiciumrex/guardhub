"use client";
import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { apiFetch } from "@/lib/api";
import type { Project } from "@/lib/types";
import { useErrorMessage } from "@/lib/use-error-message";
import { Alert } from "@/components/ui/Alert";

export function AddProjectForm() {
  const t = useTranslations("account");
  const tCommon = useTranslations("common");
  const router = useRouter();
  const errorMessage = useErrorMessage();
  const [name, setName] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const project = await apiFetch<Project>("/projects", {
        method: "POST",
        body: { name: name.trim(), target_url: targetUrl.trim() },
      });
      router.push(`/account/projects/${encodeURIComponent(project.id)}`);
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <div>
        <label htmlFor="project-name" className="gh-label">
          {t("projectName")}
        </label>
        <input
          id="project-name"
          required
          maxLength={120}
          value={name}
          onChange={(event) => setName(event.target.value)}
          className="gh-input"
        />
      </div>
      <div>
        <label htmlFor="project-url" className="gh-label">
          {t("projectUrl")}
        </label>
        <input
          id="project-url"
          type="text"
          inputMode="url"
          spellCheck={false}
          required
          maxLength={2048}
          placeholder="example.com"
          value={targetUrl}
          onChange={(event) => setTargetUrl(event.target.value)}
          className="gh-input"
        />
      </div>
      {error ? (
        <Alert tone="error" label={tCommon("errorLabel")}>
          {errorMessage(error)}
        </Alert>
      ) : null}
      <button type="submit" className="gh-btn-primary" disabled={busy}>
        {busy ? tCommon("working") : t("addSubmit")}
      </button>
    </form>
  );
}
