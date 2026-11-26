"""Verified sites (profile prompt, item 2): one status per site, a trusted-domain project listed
under its domain, a lapsed trusted domain never shown as verified."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from guardhub_api.admin.sites import build, domain_status, project_status
from guardhub_api.db.models import AdminTrustedDomain, Project

NOW = datetime(2026, 11, 26, 12, 0, tzinfo=UTC)


def _domain(
    host: str, status: str, verified_days_ago: int | None, error: str | None = None
) -> AdminTrustedDomain:
    return AdminTrustedDomain(
        id=uuid.uuid4(),
        host=host,
        target_origin=f"https://{host}",
        status=status,
        method="well_known" if verified_days_ago is not None else None,
        verified_at=NOW - timedelta(days=verified_days_ago) if verified_days_ago is not None else None,
        last_checked_at=NOW,
        last_check_error=error,
    )


def _project(
    host: str, method: str | None, verified_days_ago: int | None, paused: str | None = None
) -> Project:
    return Project(
        id=uuid.uuid4(),
        name=host,
        kind="site",
        target_url=f"https://{host}",
        ownership_method=method,
        ownership_verified_at=NOW - timedelta(days=verified_days_ago)
        if verified_days_ago is not None
        else None,
        schedule_paused_reason=paused,
    )


def test_domain_status() -> None:
    assert domain_status(_domain("a.dev", "active", 1), NOW) == "verified"
    assert domain_status(_domain("a.dev", "active", 31), NOW) == "expired"
    assert domain_status(_domain("a.dev", "suspended", 2, "timeout"), NOW) == "failed"
    assert domain_status(_domain("a.dev", "pending", None), NOW) == "pending"


def test_project_status() -> None:
    assert project_status(_project("p.dev", "well_known", 3), NOW, None) == "verified"
    assert project_status(_project("p.dev", "well_known", 40), NOW, None) == "expired"
    assert project_status(_project("p.dev", None, None), NOW, None) == "pending"
    assert project_status(_project("p.dev", "dns", 2, paused="ownership_lost"), NOW, None) == "failed"
    # proven through a trusted domain: follows the domain, and fails without one
    lapsed = _domain("p.dev", "suspended", 2, "timeout")
    assert project_status(_project("p.dev", "trusted_domain", 2), NOW, lapsed) == "failed"
    assert project_status(_project("p.dev", "trusted_domain", 2), NOW, None) == "failed"


def test_build_merges_and_orders() -> None:
    owner = _domain("guardhub.dev", "active", 0)
    news = _domain("news.example", "suspended", 2, "timeout")
    news_project = _project("news.example", "trusted_domain", 2)
    own = _project("shop.example", "meta", 5)
    rows = build([owner, news], [news_project, own], NOW)
    assert [(r.host, r.status, r.source) for r in rows] == [
        ("news.example", "failed", "trusted_domain"),
        ("guardhub.dev", "verified", "trusted_domain"),
        ("shop.example", "verified", "project"),
    ]
    assert rows[0].project_ids == [news_project.id] and rows[0].last_error == "timeout"
    assert rows[1].project_ids == []
