"""DATA_ENCRYPTION_KEY rotation CLI against a real, migrated Postgres (RLS on, app role).

The app's own key (the test DATA_ENCRYPTION_KEY) is the rotation's NEW key here, so rows created
by other integration tests are simply "already current" and stay readable by them afterwards.
"""

from __future__ import annotations

import base64
import os
import re
import uuid
from collections.abc import AsyncIterator

import pytest
from sqlalchemy import text

from guardhub_api.common.crypto import Cipher, Keyring
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.ops.rotate_encryption_key import run

NEW = base64.b64decode(os.environ["DATA_ENCRYPTION_KEY"])  # the app's current key
OLD = b"o" * 32
UNKNOWN = b"u" * 32  # a key nobody configured: rows under it can't be rotated


async def _insert_dataset(key: bytes, n_users: int = 3) -> dict[str, list[uuid.UUID]]:
    """Users with TOTP secret + Slack webhook, and a public scan with evidence, all under `key`."""
    c = Cipher(key)
    ids: dict[str, list[uuid.UUID]] = {"users": [], "evidence": [], "scans": []}
    async with db_session(DbContext.system()) as s:
        for _ in range(n_users):
            uid = uuid.uuid4()
            await s.execute(
                text("INSERT INTO users (id, email, password_hash, totp_secret) VALUES (:id, :e, 'x', :t)"),
                {
                    "id": uid,
                    "e": f"rot-{uid.hex[:12]}@example.com",
                    "t": c.encrypt(f"TOTP-{uid}", str(uid).encode()),
                },
            )
            await s.execute(
                text("INSERT INTO notification_settings (user_id, slack_webhook_enc) VALUES (:id, :w)"),
                {"id": uid, "w": c.encrypt(f"https://hooks.example.invalid/{uid}", str(uid).encode())},
            )
            ids["users"].append(uid)
        scan_id = uuid.uuid4()
        await s.execute(
            text(
                "INSERT INTO scans (id, target_url, public_token_hash, status) VALUES (:id, 'https://example.invalid', :h, 'done')"
            ),
            {"id": scan_id, "h": uuid.uuid4().hex},
        )
        ids["scans"].append(scan_id)
        for i in range(4):
            fid, eid = uuid.uuid4(), uuid.uuid4()
            await s.execute(
                text(
                    "INSERT INTO findings (id, scan_id, check_id, finding_key, severity, title_key, plain_summary,"
                    " fix_guidance, fingerprint) VALUES (:id, :s, 'exposed_env', 'k', 'info', 't', 's', 'f', :fp)"
                ),
                {"id": fid, "s": scan_id, "fp": f"{scan_id}-{i}"},
            )
            await s.execute(
                text(
                    "INSERT INTO evidence (id, finding_id, kind, location, redacted_payload) VALUES (:id, :f, 'http_response', '/.env', :p)"
                ),
                {"id": eid, "f": fid, "p": c.encrypt(f"API_KEY=****{i:04d}", str(eid).encode())},
            )
            ids["evidence"].append(eid)
    return ids


async def _values(ids: dict[str, list[uuid.UUID]]) -> dict[tuple[str, uuid.UUID], str]:
    out: dict[tuple[str, uuid.UUID], str] = {}
    async with db_session(DbContext.system()) as s:
        for uid in ids["users"]:
            out["totp", uid] = (
                await s.execute(text("SELECT totp_secret FROM users WHERE id = :i"), {"i": uid})
            ).scalar_one()
            out["slack", uid] = (
                await s.execute(
                    text("SELECT slack_webhook_enc FROM notification_settings WHERE user_id = :i"), {"i": uid}
                )
            ).scalar_one()
        for eid in ids["evidence"]:
            out["evidence", eid] = (
                await s.execute(text("SELECT redacted_payload FROM evidence WHERE id = :i"), {"i": eid})
            ).scalar_one()
    return out


async def _delete(ids: dict[str, list[uuid.UUID]]) -> None:
    async with db_session(DbContext.system()) as s:
        await s.execute(
            text("DELETE FROM scans WHERE id = ANY(:i)"), {"i": ids["scans"]}
        )  # cascades to evidence
        await s.execute(text("DELETE FROM users WHERE id = ANY(:i)"), {"i": ids["users"]})


async def _rotation_audits() -> int:
    async with db_session(DbContext.system()) as s:
        return int(
            (
                await s.execute(
                    text("SELECT count(*) FROM audit_logs WHERE action = 'ops.encryption_key_rotated'")
                )
            ).scalar_one()
        )


def _key_of(value: str, aad: uuid.UUID) -> int:
    return Keyring(NEW, [OLD]).decrypt_with_index(value, str(aad).encode())[1]


@pytest.fixture
async def old_rows() -> AsyncIterator[dict[str, list[uuid.UUID]]]:
    ids = await _insert_dataset(OLD)
    yield ids
    await _delete(ids)


async def test_rotation_moves_every_column_to_the_current_key(
    old_rows: dict[str, list[uuid.UUID]], capsys: pytest.CaptureFixture[str]
) -> None:
    before = await _values(old_rows)
    assert all(_key_of(v, aad) == 1 for (_, aad), v in before.items())
    audits = await _rotation_audits()

    # dry run: counts, but changes nothing (not even the audit log)
    assert await run(Keyring(NEW, [OLD]), batch_size=2, dry_run=True) == 0
    assert await _values(old_rows) == before
    assert await _rotation_audits() == audits
    out = capsys.readouterr().out
    assert "users.totp_secret:" in out and "would_rotate=" in out and "dry run: nothing was changed" in out

    # real run, tiny batches so several transactions are exercised
    assert await run(Keyring(NEW, [OLD]), batch_size=2) == 0
    after = await _values(old_rows)
    for (kind, aad), value in after.items():
        assert value != before[kind, aad]
        assert _key_of(value, aad) == 0
        # same plaintext, readable with the NEW key alone (the old key can now be retired)
        assert Cipher(NEW).decrypt(value, str(aad).encode()) == Cipher(OLD).decrypt(
            before[kind, aad], str(aad).encode()
        )
    assert await _rotation_audits() == audits + 1
    out = capsys.readouterr().out
    assert re.search(r"^users\.totp_secret: .* rotated=3 .* undecryptable=0$", out, re.M), out
    assert re.search(r"^evidence\.redacted_payload: .* rotated=4 .* undecryptable=0$", out, re.M), out
    assert re.search(r"^notification_settings\.slack_webhook_enc: .* rotated=3 .*", out, re.M), out

    # second run is a no-op: nothing left under a previous key, values unchanged
    assert await run(Keyring(NEW, [OLD]), batch_size=2) == 0
    assert await _values(old_rows) == after
    assert " rotated=0 " in capsys.readouterr().out

    # with the old key gone, the app (current key only) still reads everything
    assert await run(Keyring(NEW), batch_size=50) == 0


async def test_undecryptable_row_fails_and_leaves_its_batch_untouched(
    old_rows: dict[str, list[uuid.UUID]], capsys: pytest.CaptureFixture[str]
) -> None:
    bad = await _insert_dataset(UNKNOWN, n_users=1)
    try:
        before = await _values(old_rows)
        bad_before = await _values(bad)
        audits = await _rotation_audits()
        # one batch per table: the unreadable row poisons its whole batch
        assert await run(Keyring(NEW, [OLD]), batch_size=10_000) == 1
        assert await _values(old_rows) == before  # nothing half-rotated
        assert await _values(bad) == bad_before
        err = capsys.readouterr().err
        assert f"users.totp_secret row {bad['users'][0]}" in err
        assert "FAILED:" in err
        assert await _rotation_audits() == audits + 1  # the failed attempt is audited too
    finally:
        await _delete(bad)
    # once the bad row is gone (or its key is supplied), the rotation completes
    assert await run(Keyring(NEW, [OLD]), batch_size=10_000) == 0
    assert all(_key_of(v, aad) == 0 for (_, aad), v in (await _values(old_rows)).items())


async def test_missing_previous_key_changes_nothing(old_rows: dict[str, list[uuid.UUID]]) -> None:
    before = await _values(old_rows)
    # operator forgot DATA_ENCRYPTION_KEYS_PREVIOUS: every old row is unreadable → exit 1, no writes
    assert await run(Keyring(NEW), batch_size=10_000) == 1
    assert await _values(old_rows) == before
