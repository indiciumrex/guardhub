"""Published active-testing terms (final prompt item 6): only the exact file with the set hash."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from guardhub_api.config import get_settings
from guardhub_api.legal import published_terms

TEXT = b"GuardHub Active Testing Terms\nVersion 2099-01-01\n"
TR = "GuardHub Aktif Test Koşulları\n".encode()


@pytest.fixture
def terms_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    s = get_settings()
    monkeypatch.setattr(s, "legal_dir", str(tmp_path))
    monkeypatch.setattr(s, "active_tos_version", "2099-01-01")
    monkeypatch.setattr(s, "active_tos_sha256", hashlib.sha256(TEXT).hexdigest())
    return tmp_path


def test_nothing_is_published_by_default() -> None:
    assert published_terms() is None


def test_published_only_when_the_file_matches_the_hash(terms_dir: Path) -> None:
    assert published_terms() is None  # settings set, file missing
    (terms_dir / "active-testing-2099-01-01.txt").write_bytes(TEXT + b" ")
    assert published_terms() is None  # one byte changed: not the approved text
    (terms_dir / "active-testing-2099-01-01.txt").write_bytes(TEXT)
    terms = published_terms()
    assert terms is not None and terms.text == TEXT.decode() and terms.locale == "en"
    assert terms.sha256 == hashlib.sha256(TEXT).hexdigest() and terms.version == "2099-01-01"


def test_turkish_translation_falls_back_to_english(terms_dir: Path) -> None:
    (terms_dir / "active-testing-2099-01-01.txt").write_bytes(TEXT)
    assert published_terms("tr").locale == "en"  # type: ignore[union-attr]
    (terms_dir / "active-testing-2099-01-01.tr.txt").write_bytes(TR)
    tr = published_terms("tr")
    assert tr is not None and tr.locale == "tr" and tr.text == TR.decode()


def test_a_version_can_never_point_outside_the_folder(
    terms_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = terms_dir.parent / "active-testing-x.txt"
    outside.write_bytes(TEXT)
    for bad in ("../x", "a/b", "..", ""):
        monkeypatch.setattr(get_settings(), "active_tos_version", bad)
        assert published_terms() is None
