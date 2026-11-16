"""Phase 1 monitoring end-to-end (docs/architecture.md §8): schedule → due → scheduled scan on
gh:jobs → completed → alert e-mail (in-process SMTP server), diff/trend, pause on lost ownership,
notification settings, and RLS. Real PostgreSQL (RLS) + Redis + a real Arq worker in burst mode.
"""

from __future__ import annotations

import email
import socket
import threading
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email import policy
from email.message import EmailMessage

import pytest
from aiosmtpd.controller import Controller
from arq.worker import Worker
from redis.asyncio import Redis
from sqlalchemy import select, text

from guardhub_api.admin.bootstrap import _set_role
from guardhub_api.alerts import notifier
from guardhub_api.config import get_settings
from guardhub_api.db.models import AdminTrustedDomain, AuditLog, Notification, NotificationSettings, Project
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.findings.catalog import render_finding
from guardhub_api.jobs import client as jobs_client
from guardhub_api.jobs import scheduler, worker
from guardhub_api.worker import consume_once, ensure_group

from .conftest import FakeScanner, new_client, next_code, raw_finding, signed_in

SLACK_URL = "https://hooks.slack.com/services/T0000AAAA/B0000BBBB/abcdefghijklmnopqrstuvwx"


# ---- fixtures and helpers ----


@dataclass
class Mailbox:
    messages: list[tuple[list[str], EmailMessage]] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    async def handle_DATA(self, server: object, session: object, envelope: object) -> str:
        msg = email.message_from_bytes(envelope.content, policy=policy.default)  # type: ignore[attr-defined]
        with self.lock:
            self.messages.append((list(envelope.rcpt_tos), msg))  # type: ignore[attr-defined]
        return "250 OK"

    def to(self, address: str) -> list[EmailMessage]:
        with self.lock:
            return [m for rcpt, m in self.messages if address in rcpt]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture
def mailbox(monkeypatch: pytest.MonkeyPatch) -> Iterator[Mailbox]:
    box = Mailbox()
    port = _free_port()
    controller = Controller(box, hostname="127.0.0.1", port=port)
    controller.start()
    settings = get_settings()
    # A local sink: plaintext is allowed ONLY because the host is allow-listed (like mailpit).
    monkeypatch.setattr(settings, "smtp_host", "127.0.0.1")
    monkeypatch.setattr(settings, "smtp_port", port)
    monkeypatch.setattr(settings, "smtp_security", "none")
    monkeypatch.setattr(settings, "smtp_insecure_hosts", "127.0.0.1")
    monkeypatch.setattr(settings, "smtp_from", "GuardHub <alerts@guardhub.test>")
    monkeypatch.setattr(settings, "smtp_username", "")
    # earlier runs against the same database may leave scheduled scans queued: don't let them
    # eat the in-flight cap here (the cap itself is unit-tested)
    monkeypatch.setattr(settings, "scheduler_max_inflight", 50)
    yield box
    controller.stop()


async def ingest(redis: Redis) -> None:
    await ensure_group(redis)
    for _ in range(5):
        await consume_once(redis, "test-worker", block_ms=50)


async def run_jobs() -> None:
    """Run every queued Arq job once, with the production function list (burst mode)."""
    w = Worker(
        functions=worker.FUNCTIONS,
        redis_settings=jobs_client.redis_settings(),
        burst=True,
        poll_delay=0.01,
        handle_signals=False,
        job_serializer=jobs_client.serialize_job,
        job_deserializer=jobs_client.deserialize_job,
    )
    try:
        await w.main()
    finally:  # not w.close(): it signals SIGUSR1, which Windows dev shells don't have
        await w.pool.aclose()


async def set_project(project_id: str, **values: object) -> None:
    async with db_session(DbContext.system()) as session:
        project = await session.get(Project, uuid.UUID(project_id))
        assert project is not None
        for k, v in values.items():
            setattr(project, k, v)


async def audit_actions(target: str) -> list[str]:
    async with db_session(DbContext.system()) as session:
        rows = await session.execute(select(AuditLog.action).where(AuditLog.target == target))
        return list(rows.scalars().all())


def body_text(msg: EmailMessage) -> str:
    part = msg.get_body(preferencelist=("plain",))
    assert part is not None
    return str(part.get_content())


def body_html(msg: EmailMessage) -> str:
    part = msg.get_body(preferencelist=("html",))
    assert part is not None
    return str(part.get_content())


ENV = raw_finding(
    "exposed_env", "env_file_exposed", "https://mon.example/.env", {"path": "/.env", "secret_count": "3"}
)
CSP = raw_finding("security_headers", "csp_missing", "https://mon.example/")
HSTS = raw_finding("security_headers", "hsts_missing", "https://mon.example/")


async def new_verified_project(client: object, name: str, target: str) -> dict[str, object]:
    r = await client.post("/api/v1/projects", json={"name": name, "target_url": target})  # type: ignore[attr-defined]
    assert r.status_code == 201, r.text
    project = r.json()
    r = await client.post(f"/api/v1/projects/{project['id']}/verify")  # type: ignore[attr-defined]
    assert r.status_code == 200 and r.json()["verified"] is True
    return project  # type: ignore[no-any-return]


# ---- the main flow ----


async def test_schedule_scan_diff_and_change_alerts(
    redis: Redis, scanner: FakeScanner, mailbox: Mailbox
) -> None:
    async with new_client("198.51.100.201") as client:
        address, _ = await signed_in(client)  # registered with locale "tr"
        project = await new_verified_project(client, "Monitor me", "mon.example")
        pid = str(project["id"])
        assert project["scan_frequency"] == "off" and project["next_scan_at"] is None

        # 1) first scan = baseline: no alert
        scanner.findings = [ENV, CSP]
        baseline_id = (await client.post(f"/api/v1/projects/{pid}/scans")).json()["id"]
        await ingest(redis)
        await run_jobs()
        assert mailbox.to(address) == []
        diff = (await client.get(f"/api/v1/scans/{baseline_id}/diff")).json()
        assert diff["base_scan_id"] is None and diff["unchanged_count"] == 2
        assert diff["new"] == diff["regressed"] == diff["fixed"] == []

        # 2) schedule it
        r = await client.patch(f"/api/v1/projects/{pid}", json={"scan_frequency": "daily"})
        assert r.status_code == 200, r.text
        view = r.json()
        nxt = datetime.fromisoformat(view["next_scan_at"])
        now = datetime.now(UTC)
        assert view["scan_frequency"] == "daily" and view["schedule_paused_reason"] is None
        assert now + timedelta(hours=23, minutes=59) < nxt < now + timedelta(days=1, hours=1)
        assert "project.schedule_set" in await audit_actions(pid)
        r = await client.patch(f"/api/v1/projects/{pid}", json={})
        assert r.status_code == 422  # nothing to change

        # 3) it becomes due → the scheduler queues a scheduled scan on gh:jobs
        await set_project(pid, next_scan_at=now - timedelta(minutes=1))
        scanner.findings = [ENV, CSP, HSTS]
        report = await scheduler.enqueue_due_scans(redis)
        assert uuid.UUID(pid) in report.started
        scans = (await client.get(f"/api/v1/projects/{pid}/scans")).json()
        scheduled = scans[0]
        assert scheduled["trigger"] == "scheduled" and scheduled["failed_checks"] == []
        await ingest(redis)
        assert any(j["scan_id"] == scheduled["id"] for j in scanner.scan_jobs)
        view = (await client.get(f"/api/v1/projects/{pid}")).json()
        assert datetime.fromisoformat(view["next_scan_at"]) > datetime.now(UTC)  # advanced
        again = await scheduler.enqueue_due_scans(redis)  # not due any more
        assert uuid.UUID(pid) not in again.started

        # 4) completed → notify_scan → one e-mail in Turkish, listing the new issue, no evidence
        await run_jobs()
        mails = mailbox.to(address)
        assert len(mails) == 1
        mail = mails[0]
        hsts_tr = render_finding("security_headers", "hsts_missing", {}, "tr").title
        assert "Monitor me için güvenlik değişiklikleri" in mail["Subject"]
        text_part, html_part = body_text(mail), body_html(mail)
        assert "Yeni sorunlar" in text_part and hsts_tr in text_part
        assert "Bir HKSolutions ürünüdür" in text_part and "Bir HKSolutions ürünüdür" in html_part
        assert f"/account/projects/{pid}/compare/{scheduled['id']}" in text_part
        for secret in ("API_KEY", "****", "wxyz", "/.env"):
            assert secret not in text_part and secret not in html_part  # never evidence
        diff = (await client.get(f"/api/v1/scans/{scheduled['id']}/diff?locale=en")).json()
        assert diff["base_scan_id"] == baseline_id
        assert [i["finding_key"] for i in diff["new"]] == ["hsts_missing"]
        assert diff["regressed"] == diff["fixed"] == [] and diff["unchanged_count"] == 2
        assert diff["score_delta"] == -7 and diff["compared_checks"] and diff["skipped_checks"] == []
        assert "evidence" not in diff["new"][0]
        history = (await client.get("/api/v1/account/notifications/history")).json()
        assert [(h["channel"], h["status"], h["new_count"]) for h in history] == [("email", "sent", 1)]
        assert history[0]["scan_id"] == scheduled["id"] and history[0]["sent_at"]

        # idempotency: the job id is taken, and re-running the alert sends nothing new
        assert await jobs_client.enqueue_notify_scan(uuid.UUID(scheduled["id"])) is False
        assert await notifier.notify_scan(uuid.UUID(scheduled["id"]), final_try=False) == "done"
        assert len(mailbox.to(address)) == 1

        # 5) identical scan → no alert
        same_id = (await client.post(f"/api/v1/projects/{pid}/scans")).json()["id"]
        await ingest(redis)
        await run_jobs()
        assert len(mailbox.to(address)) == 1
        diff = (await client.get(f"/api/v1/scans/{same_id}/diff")).json()
        assert diff["new"] == diff["regressed"] == diff["fixed"] == [] and diff["unchanged_count"] == 3

        # 6) HSTS fixed → short "fixed" summary
        scanner.findings = [ENV, CSP]
        fixed_id = (await client.post(f"/api/v1/projects/{pid}/scans")).json()["id"]
        await ingest(redis)
        await run_jobs()
        mails = mailbox.to(address)
        assert len(mails) == 2 and "sorunlar düzeltildi" in mails[1]["Subject"]
        assert "Düzeltilenler" in body_text(mails[1])

        # 7) HSTS comes back → regression alert
        scanner.findings = [ENV, CSP, HSTS]
        back_id = (await client.post(f"/api/v1/projects/{pid}/scans")).json()["id"]
        await ingest(redis)
        await run_jobs()
        mails = mailbox.to(address)
        assert len(mails) == 3 and "Yeniden ortaya çıkan sorunlar" in body_text(mails[2])
        assert "Yeni sorunlar" not in body_text(mails[2])
        diff = (await client.get(f"/api/v1/scans/{back_id}/diff")).json()
        assert [i["finding_key"] for i in diff["regressed"]] == ["hsts_missing"] and diff["new"] == []
        # compare against an older scan explicitly
        diff = (await client.get(f"/api/v1/scans/{back_id}/diff?against={same_id}")).json()
        assert diff["base_scan_id"] == same_id and diff["new"] == diff["regressed"] == diff["fixed"] == []
        for bad in (back_id, str(uuid.uuid4()), "not-a-uuid"):
            r = await client.get(f"/api/v1/scans/{fixed_id}/diff?against={bad}")
            assert r.status_code == 422, bad  # later scan / unknown / malformed
        r = await client.get(f"/api/v1/scans/{fixed_id}/diff?against={back_id}")
        assert r.json()["error"]["code"] == "invalid_comparison"

        # 8) a check that FAILED is not reported fixed (and nothing is sent)
        scanner.failed_checks = {"exposed_env"}
        failed_id = (await client.post(f"/api/v1/projects/{pid}/scans")).json()["id"]
        await ingest(redis)
        await run_jobs()
        assert len(mailbox.to(address)) == 3
        summary = (await client.get(f"/api/v1/projects/{pid}/scans")).json()[0]
        assert summary["id"] == failed_id and summary["failed_checks"] == ["exposed_env"]
        diff = (await client.get(f"/api/v1/scans/{failed_id}/diff")).json()
        assert diff["fixed"] == [] and "exposed_env" in diff["skipped_checks"]
        assert "exposed_env" not in diff["compared_checks"]
        scanner.failed_checks = set()

        # 9) trend: done scans, oldest first, with the trigger
        trend = (await client.get(f"/api/v1/projects/{pid}/trend")).json()
        assert [t["scan_id"] for t in trend][:2] == [baseline_id, scheduled["id"]]
        assert trend[1]["trigger"] == "scheduled" and trend[-1]["scan_id"] == failed_id
        assert len((await client.get(f"/api/v1/projects/{pid}/trend?limit=2")).json()) == 2
        assert (await client.get(f"/api/v1/projects/{pid}/trend?limit=0")).status_code == 422
        assert (await client.get(f"/api/v1/projects/{pid}/trend?limit=91")).status_code == 422

        # 10) turning the schedule off clears the next run
        view = (await client.patch(f"/api/v1/projects/{pid}", json={"scan_frequency": "off"})).json()
        assert view["scan_frequency"] == "off" and view["next_scan_at"] is None


async def test_schedule_needs_verified_project(redis: Redis) -> None:
    async with new_client("198.51.100.202") as client:
        await signed_in(client)
        r = await client.post("/api/v1/projects", json={"name": "U", "target_url": "unverified.example"})
        pid = r.json()["id"]
        r = await client.patch(f"/api/v1/projects/{pid}", json={"scan_frequency": "weekly"})
        assert r.status_code == 422 and r.json()["error"]["code"] == "ownership_not_verified"
        r = await client.patch(f"/api/v1/projects/{pid}", json={"scan_frequency": "hourly"})
        assert r.status_code == 422 and r.json()["error"]["code"] == "validation_error"
        r = await client.patch(f"/api/v1/projects/{pid}", json={"name": "Renamed"})
        assert r.status_code == 200 and r.json()["name"] == "Renamed"  # rename still works


async def test_ownership_lost_pauses_schedule_and_alerts(
    redis: Redis, scanner: FakeScanner, mailbox: Mailbox
) -> None:
    async with new_client("198.51.100.203") as client:
        address, _ = await signed_in(client)
        project = await new_verified_project(client, "Lapsed", "lapsed.example")
        pid = str(project["id"])
        await client.patch(f"/api/v1/projects/{pid}", json={"scan_frequency": "weekly"})
        # the proof is older than 30 days and is gone from the site
        now = datetime.now(UTC)
        await set_project(
            pid, ownership_verified_at=now - timedelta(days=31), next_scan_at=now - timedelta(minutes=2)
        )
        scanner.verify_ok = False
        jobs_before = len(scanner.scan_jobs)
        report = await scheduler.enqueue_due_scans(redis)
        assert uuid.UUID(pid) in report.paused and uuid.UUID(pid) not in report.started
        await ingest(redis)
        assert len(scanner.scan_jobs) == jobs_before  # nothing was scanned without a proof
        view = (await client.get(f"/api/v1/projects/{pid}")).json()
        assert view["schedule_paused_reason"] == "ownership_lost"
        assert "project.schedule_paused" in await audit_actions(pid)
        assert (await client.get(f"/api/v1/projects/{pid}/scans")).json() == []

        await run_jobs()
        mails = mailbox.to(address)
        assert len(mails) == 1 and "izleme duraklatıldı" in mails[0]["Subject"]
        assert f"/account/projects/{pid}" in body_text(mails[0])

        # paused projects are not picked again, and the alert is not repeated
        await set_project(pid, next_scan_at=now - timedelta(minutes=1))
        report = await scheduler.enqueue_due_scans(redis)
        assert uuid.UUID(pid) not in report.paused + report.started
        await run_jobs()
        assert len(mailbox.to(address)) == 1

        # choosing a frequency again resumes it (the proof is re-checked before the next scan)
        view = (await client.patch(f"/api/v1/projects/{pid}", json={"scan_frequency": "weekly"})).json()
        assert view["schedule_paused_reason"] is None and view["next_scan_at"] is not None
        scanner.verify_ok = True
        await set_project(pid, next_scan_at=now - timedelta(minutes=1))
        report = await scheduler.enqueue_due_scans(redis)
        assert uuid.UUID(pid) in report.started
        verified_at = datetime.fromisoformat(
            (await client.get(f"/api/v1/projects/{pid}")).json()["ownership_verified_at"]
        )
        assert verified_at > now - timedelta(minutes=1)  # re-proven, like a manual rescan
        await ingest(redis)


async def test_trusted_domain_project_needs_an_active_domain(
    redis: Redis, scanner: FakeScanner, mailbox: Mailbox
) -> None:
    async with new_client("198.51.100.204") as client:
        address, _ = await signed_in(client)
        await _set_role(address, "admin")
        r = await client.post("/api/v1/projects", json={"name": "Trusted", "target_url": "trusted.example"})
        pid = r.json()["id"]
        now = datetime.now(UTC)
        await set_project(
            pid,
            ownership_method="trusted_domain",
            ownership_verified_at=now,
            scan_frequency="daily",
            next_scan_at=now - timedelta(minutes=1),
        )
        r = await client.post(f"/api/v1/projects/{pid}/scans")
        assert r.status_code == 422 and r.json()["error"]["code"] == "trusted_domain_inactive"
        report = await scheduler.enqueue_due_scans(redis)
        assert uuid.UUID(pid) in report.paused

        me = (await client.get("/api/v1/auth/me")).json()
        async with db_session(DbContext.system()) as session:
            session.add(
                AdminTrustedDomain(
                    admin_user_id=uuid.UUID(me["id"]),
                    host="trusted.example",
                    target_origin="https://trusted.example",
                    status="active",
                    verification_token="ghv_test-token",
                    method="well_known",
                    verified_at=now,
                )
            )
        await client.patch(f"/api/v1/projects/{pid}", json={"scan_frequency": "daily"})
        await set_project(pid, next_scan_at=now - timedelta(minutes=1))
        jobs_before = len(scanner.scan_jobs)
        report = await scheduler.enqueue_due_scans(redis)
        assert uuid.UUID(pid) in report.started
        await ingest(redis)
        assert len(scanner.scan_jobs) == jobs_before + 1
        assert scanner.scan_jobs[-1]["target"] == "https://trusted.example"
        await _set_role(address, "user")


async def test_notification_settings_slack_and_test_endpoint(redis: Redis, mailbox: Mailbox) -> None:
    async with new_client("198.51.100.205") as client:
        address, _ = await signed_in(client)
        me = (await client.get("/api/v1/auth/me")).json()
        r = await client.get("/api/v1/account/notifications")
        assert r.json() == {
            "email_enabled": True,
            "notify_new": True,
            "notify_regression": True,
            "notify_fixed": True,
            "slack_configured": False,
            "email": address,
        }
        r = await client.post("/api/v1/account/notifications/test", json={"channel": "slack"})
        assert r.status_code == 422 and r.json()["error"]["code"] == "slack_not_configured"

        flags = {"email_enabled": True, "notify_new": True, "notify_regression": False, "notify_fixed": True}
        for bad in (
            "https://evil.example/services/T0000AAAA/B0000BBBB/abcdefghij",
            "http://hooks.slack.com/x",
        ):
            r = await client.put("/api/v1/account/notifications", json={**flags, "slack_webhook_url": bad})
            assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_slack_webhook"
        r = await client.put("/api/v1/account/notifications", json={**flags, "slack_webhook_url": SLACK_URL})
        assert r.status_code == 200 and r.json()["slack_configured"] is True
        assert "hooks.slack.com" not in r.text and r.json()["notify_regression"] is False
        assert "hooks.slack.com" not in (await client.get("/api/v1/account/notifications")).text

        async with db_session(DbContext.system()) as session:
            row = await session.get(NotificationSettings, uuid.UUID(me["id"]))
            assert row is not None and row.slack_webhook_enc is not None
            assert row.slack_webhook_enc.startswith("v1.") and "slack" not in row.slack_webhook_enc
            meta = (
                (
                    await session.execute(
                        text(
                            "SELECT metadata::text FROM audit_logs WHERE action = 'account.notifications_updated' "
                            "AND target = :t"
                        ),
                        {"t": me["id"]},
                    )
                )
                .scalars()
                .all()
            )
        assert meta and all("hooks" not in m for m in meta)

        # omitted = keep; null = remove
        r = await client.put("/api/v1/account/notifications", json=flags)
        assert r.json()["slack_configured"] is True
        r = await client.put("/api/v1/account/notifications", json={**flags, "slack_webhook_url": None})
        assert r.json()["slack_configured"] is False
        r = await client.put("/api/v1/account/notifications", json={**flags, "unknown": 1})
        assert r.status_code == 422

        # test sends: 3 attempts per hour (the refused Slack one above counted), delivered by
        # api-jobs in the user's language
        codes = [
            (await client.post("/api/v1/account/notifications/test", json={"channel": "email"})).status_code
            for _ in range(3)
        ]
        assert codes == [202, 202, 429]
        await run_jobs()
        mails = mailbox.to(address)
        assert len(mails) == 2 and all("test bildirimi" in m["Subject"] for m in mails)
        assert "Bir HKSolutions ürünüdür" in body_text(mails[0])


async def test_other_users_get_404_and_see_no_settings_or_history(redis: Redis, scanner: FakeScanner) -> None:
    async with new_client("198.51.100.206") as alice, new_client("198.51.100.207") as bob:
        await signed_in(alice)
        bob_email, bob_secret = await signed_in(bob)
        project = await new_verified_project(alice, "Alice", "alice-mon.example")
        pid = str(project["id"])
        scanner.findings = [CSP]
        scan_id = (await alice.post(f"/api/v1/projects/{pid}/scans")).json()["id"]
        await ingest(redis)
        alice_me = (await alice.get("/api/v1/auth/me")).json()
        async with db_session(DbContext.system()) as session:
            session.add(
                Notification(
                    user_id=uuid.UUID(alice_me["id"]),
                    project_id=uuid.UUID(pid),
                    scan_id=uuid.UUID(scan_id),
                    channel="email",
                    status="sent",
                    new_count=1,
                )
            )
        assert len((await alice.get("/api/v1/account/notifications/history")).json()) == 1
        assert (await alice.get(f"/api/v1/scans/{scan_id}/diff")).status_code == 200

        async def bob_sees_nothing() -> None:
            assert (await bob.get(f"/api/v1/scans/{scan_id}/diff")).status_code == 404
            assert (await bob.get(f"/api/v1/projects/{pid}/trend")).status_code == 404
            assert (await bob.get(f"/api/v1/projects/{pid}")).status_code == 404
            r = await bob.patch(f"/api/v1/projects/{pid}", json={"scan_frequency": "off"})
            assert r.status_code == 404
            assert (await bob.post(f"/api/v1/projects/{pid}/scans")).status_code == 404
            assert (await bob.delete(f"/api/v1/projects/{pid}")).status_code == 404
            assert (await bob.get("/api/v1/account/notifications/history")).json() == []
            settings = (await bob.get("/api/v1/account/notifications")).json()
            assert settings["email"] == bob_email and settings["slack_configured"] is False

        await bob_sees_nothing()
        # An ADMIN session can READ other users' rows under RLS: the owner checks must still hold.
        await _set_role(bob_email, "admin")
        await bob.post("/api/v1/auth/logout")
        await bob.post("/api/v1/auth/login", json={"email": bob_email, "password": "a-Strong-passphrase-42"})
        r = await bob.post("/api/v1/auth/2fa/verify", json={"code": next_code(bob_secret)})
        assert r.status_code == 200 and r.json()["user"]["role"] == "admin"
        await bob_sees_nothing()
        await _set_role(bob_email, "user")
        assert (await alice.get(f"/api/v1/projects/{pid}")).status_code == 200  # untouched

    # and the database itself hides Alice's alert rows from Bob's RLS context
    async with db_session(DbContext.system()) as session:
        bob_id = (
            await session.execute(text("SELECT id FROM users WHERE email = :e"), {"e": bob_email})
        ).scalar_one()
    async with db_session(DbContext.for_user(bob_id, "user")) as session:
        rows = (await session.execute(select(Notification))).scalars().all()
        assert rows == []
        assert (await session.execute(select(NotificationSettings))).scalars().all() == []
