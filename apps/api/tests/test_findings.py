from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from guardhub_api.config import get_settings
from guardhub_api.findings.catalog import TEXT_FIELDS, render_finding, render_template
from guardhub_api.findings.contract_gen import CHECK_FINDING_KEYS, CHECK_IDS
from guardhub_api.findings.scoring import compute_score, count_by_severity
from guardhub_api.scans.ingest import validate_findings


def _raw(check_id: str, key: str, severity: str = "info", location: str = "https://example.com/.env") -> dict:
    fp = hashlib.sha256(f"{check_id}|{key}|{location}".encode()).hexdigest()
    return {
        "check_id": check_id,
        "finding_key": key,
        "severity": severity,
        "params": {"path": "/.env", "secret_count": "3"},
        "evidence": {
            "kind": "http_response",
            "location": location,
            "redacted_payload": "DB_PASSWORD=****abcd",
        },
        "fingerprint": fp,
    }


def test_score_is_deterministic_and_floored() -> None:
    assert compute_score([]) == 100
    assert compute_score(["critical", "high", "medium", "low", "info"]) == 100 - 30 - 15 - 7 - 2
    assert compute_score(["critical"] * 10) == 0
    assert count_by_severity(["low", "low", "high"]) == {
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 2,
        "info": 0,
    }


def test_render_template_is_not_str_format() -> None:
    assert (
        render_template("Found {path} ({secret_count})", {"path": "/.env", "secret_count": "3"})
        == "Found /.env (3)"
    )
    # attribute/index access and unknown names are left alone (no format-string injection)
    assert (
        render_template("{path.__class__} {x[0]} {missing}", {"path": "p"})
        == "{path.__class__} {x[0]} {missing}"
    )
    assert render_template("{path}", {"path": "{secret_count}"}) == "{secret_count}"


def test_validate_findings_enforces_contract() -> None:
    good = _raw("exposed_env", "env_file_exposed", severity="low")  # wrong severity on purpose
    dup = dict(good)
    unknown_key = _raw("exposed_env", "made_up_key", location="https://example.com/a")
    not_requested = _raw("tls_cert", "cert_expired", location="https://example.com/b")
    bad_fp = {
        **_raw("exposed_env", "git_repository_exposed", location="https://example.com/c"),
        "fingerprint": "zz",
    }
    extra_field = {**_raw("exposed_env", "git_repository_exposed", location="https://e.com/d"), "evil": True}
    out = validate_findings(
        [good, dup, unknown_key, not_requested, bad_fp, extra_field, "junk"], {"exposed_env"}
    )
    assert len(out) == 1
    assert out[0].severity == "critical"  # catalog severity wins over the scanner-supplied one
    assert validate_findings("not a list", {"exposed_env"}) == []


def test_every_catalog_key_has_curated_en_and_tr_texts() -> None:
    """§7.5: en is the source and must be complete; tr is complete for the MVP."""
    shared = get_settings().shared_dir
    catalog = json.loads((shared / "check-ids.json").read_text(encoding="utf-8"))
    declared = {c["id"]: c for c in catalog["checks"]}
    assert set(declared) == set(CHECK_IDS)
    for locale in ("en", "tr"):
        texts = json.loads((shared / "i18n" / locale / "checks.json").read_text(encoding="utf-8"))
        for check_id, check in declared.items():
            assert texts[check_id]["name"], (locale, check_id)
            assert texts[check_id]["description"], (locale, check_id)
            for fk in check["finding_keys"]:
                entry = texts[check_id]["findings"][fk["key"]]
                for field in TEXT_FIELDS:
                    assert entry[field].strip(), (locale, check_id, fk["key"], field)
                # every placeholder used must be a declared param
                used = set(__import__("re").findall(r"\{([a-z_][a-z0-9_]*)\}", " ".join(entry.values())))
                assert used <= set(fk["params"]), (locale, check_id, fk["key"], used)


@pytest.mark.parametrize("locale", ["en", "tr", "de"])
def test_render_finding_localises_with_fallback(locale: str) -> None:
    rendered = render_finding(
        "exposed_env", "env_file_exposed", {"path": "/.env", "secret_count": "3"}, locale
    )
    for field in TEXT_FIELDS:
        value = getattr(rendered, field)
        assert value and not value.startswith("[exposed_env.")
    if locale == "de":  # no curated German yet → English fallback, never machine translation
        assert rendered == render_finding(
            "exposed_env", "env_file_exposed", {"path": "/.env", "secret_count": "3"}, "en"
        )


def test_generated_contract_matches_catalog() -> None:
    shared = Path(get_settings().shared_dir)
    catalog = json.loads((shared / "check-ids.json").read_text(encoding="utf-8"))
    expected = {c["id"]: {fk["key"]: fk["severity"] for fk in c["finding_keys"]} for c in catalog["checks"]}
    assert expected == CHECK_FINDING_KEYS
