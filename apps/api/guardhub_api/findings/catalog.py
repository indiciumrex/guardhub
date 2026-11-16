"""Curated check-text catalog loader (§7.5). Plain-language texts come ONLY from here.

Reads packages/shared/i18n/<locale>/checks.json once and falls back to `en` per missing key.
There's no runtime machine translation: an unknown key renders the English text, and if that's
missing too, an explicit marker string (which the CI i18n gate prevents from shipping).
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import TypedDict, cast

from guardhub_api.common.request_meta import DEFAULT_LOCALE, SUPPORTED_LOCALES
from guardhub_api.config import get_settings

log = logging.getLogger("guardhub.findings.catalog")

_PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*)\}")
TEXT_FIELDS = ("title", "summary", "why", "fix")


class FindingTexts(TypedDict, total=False):
    title: str
    summary: str
    why: str
    fix: str


class CheckTexts(TypedDict, total=False):
    name: str
    description: str
    findings: dict[str, FindingTexts]


@dataclass(frozen=True, slots=True)
class RenderedFinding:
    title: str
    summary: str
    why: str
    fix: str


def _load_locale(shared_dir: Path, locale: str) -> dict[str, CheckTexts]:
    path = shared_dir / "i18n" / locale / "checks.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        log.exception("invalid_i18n_file", extra={"path": str(path)})
        return {}
    return cast(dict[str, CheckTexts], data) if isinstance(data, dict) else {}


@lru_cache(maxsize=1)
def _catalog() -> dict[str, dict[str, CheckTexts]]:
    shared = get_settings().shared_dir
    return {loc: _load_locale(shared, loc) for loc in SUPPORTED_LOCALES}


def reload_catalog() -> None:
    _catalog.cache_clear()


def render_template(template: str, params: dict[str, str]) -> str:
    """Replace `{name}` placeholders with params. There's no attribute or index access (unlike
    str.format), so a param value can't trigger formatting. Unknown placeholders stay visible."""
    return _PLACEHOLDER.sub(lambda m: params.get(m.group(1), m.group(0)), template)


def _lookup(locale: str, check_id: str) -> CheckTexts:
    return _catalog().get(locale, {}).get(check_id, {})


def check_name(check_id: str, locale: str) -> str:
    return _lookup(locale, check_id).get("name") or _lookup(DEFAULT_LOCALE, check_id).get("name") or check_id


def check_description(check_id: str, locale: str) -> str:
    return _lookup(locale, check_id).get("description") or _lookup(DEFAULT_LOCALE, check_id).get(
        "description", ""
    )


def render_finding(check_id: str, finding_key: str, params: dict[str, str], locale: str) -> RenderedFinding:
    primary = _lookup(locale, check_id).get("findings", {}).get(finding_key, {})
    fallback = _lookup(DEFAULT_LOCALE, check_id).get("findings", {}).get(finding_key, {})
    out: dict[str, str] = {}
    for field in TEXT_FIELDS:
        template = primary.get(field) or fallback.get(field)
        if template is None:
            log.error(
                "missing_check_text", extra={"check_id": check_id, "finding_key": finding_key, "f": field}
            )
            template = f"[{check_id}.{finding_key}.{field}]"
        out[field] = render_template(str(template), params)
    return RenderedFinding(**out)


def text_key(check_id: str, finding_key: str, field: str) -> str:
    return f"checks.{check_id}.findings.{finding_key}.{field}"
