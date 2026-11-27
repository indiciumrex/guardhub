"""The published active-testing terms (final prompt item 6): the exact text customers consent to.

The text is never in the repository. The founder places the approved file on the server
(LEGAL_DIR, mounted read-only) as `active-testing-<version>.txt` (+ `.tr.txt` for the Turkish
translation) and sets ACTIVE_TOS_VERSION and ACTIVE_TOS_SHA256. The terms count as published
only when the English file's SHA-256 equals ACTIVE_TOS_SHA256: a missing, changed or unreadable
file means "not published", the page answers 404, and every customer active scan stays refused.
"""

from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Query
from pydantic import BaseModel

from guardhub_api.common.errors import NotFoundError
from guardhub_api.config import get_settings

log = logging.getLogger(__name__)

MAX_BYTES = 64 * 1024
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")  # no path separators, no ".."
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class PublishedTerms(BaseModel):
    version: str
    sha256: str  # of the English (canonical) text
    locale: Literal["en", "tr"]  # the language of `text` (English when no translation is placed)
    text: str


def _read(path: Path) -> bytes | None:
    try:
        if not path.is_file() or path.stat().st_size > MAX_BYTES:
            return None
        return path.read_bytes()
    except OSError:
        return None


def published_terms(locale: str = "en") -> PublishedTerms | None:
    s = get_settings()
    version = s.active_tos_version.strip()
    digest = s.active_tos_sha256.strip().lower()
    if not s.legal_dir or not _VERSION_RE.match(version) or ".." in version or not _SHA_RE.match(digest):
        return None
    base = Path(s.legal_dir)
    canonical = _read(base / f"active-testing-{version}.txt")
    if canonical is None or hashlib.sha256(canonical).hexdigest() != digest:
        if canonical is not None:
            log.warning("active_terms_hash_mismatch", extra={"version": version})
        return None
    try:
        text = canonical.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if locale == "tr":
        translated = _read(base / f"active-testing-{version}.tr.txt")
        try:
            if translated is not None:
                return PublishedTerms(
                    version=version, sha256=digest, locale="tr", text=translated.decode("utf-8")
                )
        except UnicodeDecodeError:
            pass  # a broken translation falls back to the canonical English text
    return PublishedTerms(version=version, sha256=digest, locale="en", text=text)


router = APIRouter(prefix="/legal", tags=["legal"])


@router.get("/active-testing")
async def active_testing_terms(locale: Literal["en", "tr"] = Query("en")) -> PublishedTerms:
    """Public: the exact terms text customers consent to, or 404 while none is published."""
    terms = published_terms(locale)
    if terms is None:
        raise NotFoundError("terms_not_published", "The active-testing terms are not published yet.")
    return terms
