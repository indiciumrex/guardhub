"""i18n gate (GUARDHUB_STANDARDS §7.5, §10).

- `en` is the source: every check/finding key in check-ids.json must have curated title, summary,
  why and fix texts, and ui.json must exist. Missing → FAIL.
- `tr` is complete for the MVP: any key missing vs. `en` (checks.json and ui.json) → FAIL.
- The other locales fall back to `en`: missing keys → WARNING only (shown in the CI log).
- Placeholders must match the params declared in check-ids.json in every locale → FAIL.
- notifications.json (alert e-mail/Slack texts, docs/architecture.md §8.4): `en` must exist with no
  empty text, `tr` must have every `en` key → FAIL; other locales fall back → WARNING. In every
  locale, keys must exist in `en` and use exactly the same `{placeholders}` as `en` → FAIL.

Usage: python ops/ci/check_i18n.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SHARED = ROOT / "packages" / "shared"
LOCALES = ("en", "de", "tr", "fr", "it", "es", "zh-CN", "hi", "ru")
COMPLETE = ("en", "tr")
FIELDS = ("title", "summary", "why", "fix")
PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*)\}")


def _load(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def _flatten(obj: object, prefix: str = "") -> dict[str, str]:
    out: dict[str, str] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(_flatten(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(obj, str):
        out[prefix] = obj
    return out


def check_notifications(errors: list[str], warnings: list[str]) -> None:
    en = _flatten(_load(SHARED / "i18n" / "en" / "notifications.json"))
    if not en:
        errors.append("en/notifications.json is missing or empty")
        return
    errors.extend(f"[en] notifications.{k} is empty" for k, v in en.items() if not v.strip())
    for locale in LOCALES:
        if locale == "en":
            continue
        texts = _flatten(_load(SHARED / "i18n" / locale / "notifications.json"))
        missing = sorted(k for k in en if not texts.get(k, "").strip())
        if missing:
            (errors if locale in COMPLETE else warnings).append(
                f"[{locale}] notifications.json missing {len(missing)} keys (falls back to en)"
                + (f": {missing[:10]}" if locale in COMPLETE else "")
            )
        extra = sorted(set(texts) - set(en))
        if extra:
            errors.append(f"[{locale}] notifications.json has keys not in en: {extra[:10]}")
        for key in sorted(set(texts) & set(en)):
            want, got = set(PLACEHOLDER.findall(en[key])), set(PLACEHOLDER.findall(texts[key]))
            if want != got:
                errors.append(
                    f"[{locale}] notifications.{key} placeholders {sorted(got)} != en {sorted(want)}"
                )


def main() -> int:
    catalog = json.loads((SHARED / "check-ids.json").read_text(encoding="utf-8"))
    errors: list[str] = []
    warnings: list[str] = []

    en_checks = _load(SHARED / "i18n" / "en" / "checks.json")
    en_ui = _flatten(_load(SHARED / "i18n" / "en" / "ui.json"))
    if not en_ui:
        errors.append("en/ui.json is missing or empty")

    for locale in LOCALES:
        checks = _load(SHARED / "i18n" / locale / "checks.json")
        report = errors if locale in COMPLETE else warnings
        for check in catalog["checks"]:
            cid = check["id"]
            entry = checks.get(cid, {})
            assert isinstance(entry, dict)
            for meta in ("name", "description"):
                if not str(entry.get(meta, "")).strip():
                    report.append(f"[{locale}] checks.{cid}.{meta} missing")
            findings = entry.get("findings", {})
            assert isinstance(findings, dict)
            for fk in check["finding_keys"]:
                texts = findings.get(fk["key"], {})
                assert isinstance(texts, dict)
                for field in FIELDS:
                    value = str(texts.get(field, "")).strip()
                    if not value:
                        report.append(f"[{locale}] checks.{cid}.findings.{fk['key']}.{field} missing")
                        continue
                    unknown = set(PLACEHOLDER.findall(value)) - set(fk["params"])
                    if unknown:
                        errors.append(
                            f"[{locale}] checks.{cid}.findings.{fk['key']}.{field} uses undeclared {sorted(unknown)}"
                        )
        if locale != "en":
            ui = _flatten(_load(SHARED / "i18n" / locale / "ui.json"))
            missing_ui = sorted(set(en_ui) - set(ui))
            if missing_ui:
                (errors if locale in COMPLETE else warnings).append(
                    f"[{locale}] ui.json missing {len(missing_ui)} keys (falls back to en)"
                    + (f": {missing_ui[:10]}" if locale in COMPLETE else "")
                )
            extra = sorted(set(ui) - set(en_ui))
            if extra:
                errors.append(f"[{locale}] ui.json has keys not in en: {extra[:10]}")

    if not en_checks:
        errors.append("en/checks.json is missing")
    check_notifications(errors, warnings)
    for w in warnings:
        print(f"::warning::i18n {w}")
    for e in errors:
        print(f"::error::i18n {e}")
    print(f"i18n: {len(errors)} errors, {len(warnings)} warnings")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
