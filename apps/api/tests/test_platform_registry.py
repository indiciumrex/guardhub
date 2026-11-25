"""Admin configuration (Prompt 2 §1): only bounded, typed tunables, never security controls."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import SecretStr

from guardhub_api.config import get_settings
from guardhub_api.platform import registry, service
from guardhub_api.platform.registry import BY_KEY, FORBIDDEN_KEY_PARTS, TUNABLES, InvalidValueError, coerce

PKG = Path(__file__).resolve().parents[1] / "guardhub_api"


def test_no_tunable_touches_active_testing_ownership_or_auth() -> None:
    for t in TUNABLES:
        assert not [w for w in FORBIDDEN_KEY_PARTS if w in t.key], t.key


@pytest.mark.parametrize(
    "path",
    [
        "active",
        "admin/trusted_domains",
        "projects/verification.py",
        "modules/accuracy.py",
        "modules/registry.py",
        "auth/security.py",
    ],
)
def test_security_code_never_reads_runtime_settings(path: str) -> None:
    """The four active-testing locks and ownership proof stay in code: they never import platform."""
    target = PKG / path
    files = [target] if target.is_file() else sorted(target.rglob("*.py"))
    assert files, path
    for f in files:
        assert "guardhub_api.platform" not in f.read_text(encoding="utf-8"), f


def test_defaults_are_todays_behaviour() -> None:
    s = get_settings()
    assert BY_KEY["scan.deadline_seconds"].default() == s.scan_deadline_seconds
    assert BY_KEY["scheduler.batch"].default() == s.scheduler_batch
    assert BY_KEY["scheduler.max_inflight"].default() == s.scheduler_max_inflight
    assert BY_KEY["maintenance.enabled"].default() is False
    assert all(
        BY_KEY[k].default() is True
        for k in ("flags.public_scan", "flags.registration", "flags.scheduled_scans")
    )
    assert [BY_KEY[k].default() for k in ("rate.challenge_per_ip_hour", "rate.anon_scan_per_ip_hour",
            "rate.anon_scan_per_target_hour", "rate.rescan_per_project_hour", "rate.register_per_ip_hour")] == [
        10, 5, 5, 10, 5]  # fmt: skip
    for t in TUNABLES:  # every default is itself a valid value
        assert coerce(t, t.default()) == t.default()


@pytest.mark.parametrize(
    ("key", "raw"),
    [
        ("scan.deadline_seconds", 29),
        ("scan.deadline_seconds", 301),
        ("scan.deadline_seconds", "120"),
        ("scan.deadline_seconds", True),
        ("scan.deadline_seconds", 60.5),
        ("rate.anon_scan_per_ip_hour", 0),
        ("rate.anon_scan_per_ip_hour", 21),
        ("flags.registration", "false"),
        ("flags.registration", 0),
        ("maintenance.message", "x" * 281),
        ("maintenance.message", "line\nbreak"),
        ("maintenance.message", 5),
    ],
)
def test_out_of_bounds_or_wrong_type_is_refused(key: str, raw: object) -> None:
    with pytest.raises(InvalidValueError):
        coerce(BY_KEY[key], raw)


def test_valid_values() -> None:
    assert coerce(BY_KEY["scan.deadline_seconds"], 300) == 300
    assert coerce(BY_KEY["flags.public_scan"], False) is False
    assert coerce(BY_KEY["maintenance.message"], "  Back at 14:00 UTC  ") == "Back at 14:00 UTC"


def test_environment_never_shows_a_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "s3cr3t-value-that-must-not-leak"
    s = get_settings().model_copy(update={"jwt_secret": SecretStr(secret), "smtp_username": "mailer-user",
                                          "ai_api_key": SecretStr("")})  # fmt: skip
    rows = service.environment(s)
    dumped = json.dumps([r.model_dump() for r in rows])
    assert secret not in dumped
    assert "mailer-user" not in dumped  # not on the visible list: shown as set / not set only
    by = {r.name: r for r in rows}
    assert (
        by["jwt_secret"].kind == "secret" and by["jwt_secret"].configured and by["jwt_secret"].value is None
    )
    assert by["ai_api_key"].kind == "secret" and not by["ai_api_key"].configured
    assert by["smtp_username"].kind == "hidden" and by["smtp_username"].configured
    assert by["database_url"].kind == "secret"
    assert by["active_testing_approved"].kind == "value"  # shown, never editable


def test_registry_keys_match_the_database_check() -> None:
    import re

    for t in registry.TUNABLES:
        assert re.fullmatch(r"[a-z_]+(\.[a-z_]+)+", t.key) and len(t.key) <= 64
