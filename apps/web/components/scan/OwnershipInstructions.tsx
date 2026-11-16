/**
 * The three ways to prove ownership of a site (ADR-0001), each with copyable values.
 * Used by the free scan flow and the project page.
 */
import { useTranslations } from "next-intl";
import { CopyField } from "@/components/ui/CopyField";
import type { OwnershipInstructions as Instructions } from "@/lib/types";

export function OwnershipInstructions({
  token,
  instructions,
}: {
  token: string;
  instructions: Instructions;
}) {
  const t = useTranslations("ownership");
  return (
    <div className="space-y-4">
      <p className="gh-muted">{t("intro")}</p>
      <ol className="space-y-4">
        <li className="gh-card p-5">
          <h3 className="font-semibold">{t("wellKnown.title")}</h3>
          <p className="gh-muted mt-1 text-sm">{t("wellKnown.body")}</p>
          <div className="mt-3 space-y-3">
            <CopyField label={t("wellKnown.urlLabel")} value={instructions.well_known_url} />
            <CopyField label={t("wellKnown.contentLabel")} value={token} />
          </div>
        </li>
        <li className="gh-card p-5">
          <h3 className="font-semibold">{t("meta.title")}</h3>
          <p className="gh-muted mt-1 text-sm">{t("meta.body")}</p>
          <div className="mt-3">
            <CopyField label={t("meta.tagLabel")} value={instructions.meta_tag} />
          </div>
        </li>
        <li className="gh-card p-5">
          <h3 className="font-semibold">{t("dns.title")}</h3>
          <p className="gh-muted mt-1 text-sm">{t("dns.body")}</p>
          <div className="mt-3 space-y-3">
            <CopyField label={t("dns.nameLabel")} value={instructions.dns_name} />
            <CopyField label={t("dns.valueLabel")} value={instructions.dns_value} />
          </div>
        </li>
      </ol>
    </div>
  );
}
