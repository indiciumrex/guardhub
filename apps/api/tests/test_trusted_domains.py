"""Unit tests for admin trusted domains (ADR-0003): state transitions, the 404 gate, the
ownership helper's role check, and the background re-check's bounded concurrency. No DB/Redis."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import pytest

from guardhub_api.admin.trusted_domains import jobs, ownership, router, service
from guardhub_api.auth.security import SessionClaims, issue_session
from guardhub_api.common.errors import NotFoundError, UnauthenticatedError, UnprocessableError
from guardhub_api.db.models import AdminTrustedDomain
from guardhub_api.scans.queue import VerifyResult

NOW = datetime(2026, 11, 17, 4, 10, tzinfo=UTC)


def _domain(status: str) -> AdminTrustedDomain:
    return AdminTrustedDomain(
        id=uuid.uuid4(),
        admin_user_id=uuid.uuid4(),
        host="example.com",
        target_origin="https://example.com",
        status=status,
        verification_token="ghv_test",
        created_at=NOW,
    )


def _claims(*, mfa: bool = True) -> SessionClaims:
    return issue_session(user_id=uuid.uuid4(), role="admin", mfa=mfa, ttl_seconds=600)


def test_host_of_origin_keeps_port_and_drops_scheme() -> None:
    assert service.host_of_origin("https://example.com") == "example.com"
    assert service.host_of_origin("http://example.com:8080") == "example.com:8080"


@pytest.mark.parametrize(
    ("before", "verb"), [("pending", "verified"), ("suspended", "reactivated"), ("active", None)]
)
def test_mark_proven_activates_and_names_the_transition(before: str, verb: str | None) -> None:
    domain = _domain(before)
    domain.suspended_at = NOW
    domain.last_check_error = "not_found"
    assert service.mark_proven(domain, "dns_txt", NOW) == verb
    assert domain.status == "active"
    assert (domain.method, domain.verified_at, domain.last_checked_at) == ("dns_txt", NOW, NOW)
    assert domain.suspended_at is None and domain.last_check_error is None


def test_mark_failed_suspends_only_active_domains() -> None:
    active = _domain("active")
    assert service.mark_failed(active, "not_found", NOW) is True
    assert (active.status, active.suspended_at, active.last_check_error) == ("suspended", NOW, "not_found")

    for status in ("pending", "suspended"):
        domain = _domain(status)
        assert service.mark_failed(domain, "timeout", NOW) is False
        assert domain.status == status and domain.last_checked_at == NOW


def test_view_rejects_unknown_status() -> None:
    domain = _domain("bogus")
    with pytest.raises(ValueError, match="bogus"):
        service._view(domain)


async def test_gate_hides_routes_without_a_full_admin_session(monkeypatch: pytest.MonkeyPatch) -> None:
    roles: dict[uuid.UUID, str] = {}

    async def current_role(user_id: uuid.UUID) -> str:
        if user_id not in roles:
            raise UnauthenticatedError("session_invalid", "gone")
        return roles[user_id]

    monkeypatch.setattr(router.auth_service, "current_role", current_role)

    with pytest.raises(NotFoundError):
        await router.trusted_domains_admin(None)  # signed out
    pre_mfa = _claims(mfa=False)
    roles[pre_mfa.user_id] = "admin"
    with pytest.raises(NotFoundError):
        await router.trusted_domains_admin(pre_mfa)  # admin, but 2FA not finished
    demoted = _claims()
    roles[demoted.user_id] = "user"  # the token still says admin; the DB wins
    with pytest.raises(NotFoundError):
        await router.trusted_domains_admin(demoted)
    with pytest.raises(NotFoundError):
        await router.trusted_domains_admin(_claims())  # user row gone
    admin = _claims()
    roles[admin.user_id] = "admin"
    assert await router.trusted_domains_admin(admin) is admin


async def test_ownership_helper_refuses_non_admins_without_touching_domains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def role_user(_: uuid.UUID) -> str:
        return "user"

    monkeypatch.setattr(ownership.auth_service, "current_role", role_user)
    assert await ownership.trusted_domain_covers(uuid.uuid4(), "https://example.com") is False
    with pytest.raises(UnprocessableError) as exc:
        await ownership.require_trusted_domain(uuid.uuid4(), "https://example.com")
    assert exc.value.code == "trusted_domain_inactive"


async def test_recheck_runs_at_most_two_checks_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    ids = [uuid.uuid4() for _ in range(7)]
    verdicts = dict(zip(ids, ["confirmed", "suspended", "reactivated", "still_suspended", "confirmed",
                               "skipped", "confirmed"], strict=True))  # fmt: skip
    running = 0
    peak = 0

    @asynccontextmanager
    async def fake_session(_: object) -> AsyncIterator[None]:
        yield None

    async def fake_ids(_: object) -> list[uuid.UUID]:
        return ids

    async def fake_load(domain_id: uuid.UUID) -> tuple[str, str] | None:
        return None if verdicts[domain_id] == "skipped" else ("https://example.com", "ghv_x")

    async def fake_verify(*_: object, **__: object) -> VerifyResult:
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        await asyncio.sleep(0.01)
        running -= 1
        return VerifyResult(verified=True, method="well_known", error=None)

    async def fake_apply(domain_id: uuid.UUID, _: VerifyResult) -> str:
        return verdicts[domain_id]

    monkeypatch.setattr(jobs, "db_session", fake_session)
    monkeypatch.setattr(jobs.repository, "ids_to_recheck", fake_ids)
    monkeypatch.setattr(jobs, "_load_target", fake_load)
    monkeypatch.setattr(jobs.queue, "request_verification", fake_verify)
    monkeypatch.setattr(jobs, "_apply", fake_apply)
    monkeypatch.setattr(jobs, "get_redis", lambda: None)

    counts = await jobs.recheck_trusted_domains({})
    assert peak == jobs.RECHECK_CONCURRENCY == 2
    assert counts == {
        "checked": 6,
        "confirmed": 3,
        "reactivated": 1,
        "suspended": 1,
        "still_suspended": 1,
        "skipped": 1,
        "errors": 0,
    }
