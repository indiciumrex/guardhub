"""Operator CLI: re-encrypt every encrypted column with the CURRENT `DATA_ENCRYPTION_KEY`.

  docker exec guardhub-api-1 python -m guardhub_api.ops.rotate_encryption_key [--dry-run] [--batch-size N]

Reads each value with the keyring (current key, then DATA_ENCRYPTION_KEYS_PREVIOUS in order),
skips values already under the current key (so a re-run is a no-op), and rewrites the rest in
batches, one transaction each, as the 'system' DB context. Every rewritten value is read back and
decrypted with the current key before its batch commits. If ANY value in a batch can't be
decrypted with any configured key, that batch is rolled back untouched and the exit code is 1.
The run is audited as `ops.encryption_key_rotated` (counts only, never values or keys). It does
NOT change keys or the environment: see "Rotating DATA_ENCRYPTION_KEY" in
ops/runbooks/production.md.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import uuid
from dataclasses import dataclass, field

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.common import audit
from guardhub_api.common.crypto import DecryptionError, Keyring
from guardhub_api.config import get_settings
from guardhub_api.db.session import DbContext, db_session, dispose_engine


@dataclass(frozen=True, slots=True)
class EncryptedColumn:
    """One AES-GCM column. The AAD is the text form of `aad_column` (a uuid) of the same row."""

    table: str
    pk: str
    column: str
    aad_column: str

    @property
    def name(self) -> str:
        return f"{self.table}.{self.column}"


# EVERY column written with Cipher/Keyring.encrypt must be listed here (and in the restore drill
# in ops/deploy/guardhub-ctl.sh), or a rotation would leave it under a key that later goes away.
ENCRYPTED_COLUMNS: tuple[EncryptedColumn, ...] = (
    EncryptedColumn("users", "id", "totp_secret", "id"),
    EncryptedColumn("evidence", "id", "redacted_payload", "id"),
    EncryptedColumn("notification_settings", "user_id", "slack_webhook_enc", "user_id"),
    EncryptedColumn("webhooks", "id", "secret_enc", "id"),  # signing secrets (Prompt 2 section 4)
)


@dataclass(slots=True)
class ColumnReport:
    present: bool = True
    scanned: int = 0
    current: int = 0  # already under the current key
    rotated: int = 0  # rewritten (or, with --dry-run, would be)
    changed_meanwhile: int = 0  # the app rewrote the value during the run (always with the current key)
    failed: list[uuid.UUID] = field(default_factory=list)

    def line(self, name: str, dry_run: bool) -> str:
        if not self.present:
            return f"{name}: column not present in this schema, skipped"
        verb = "would_rotate" if dry_run else "rotated"
        return (
            f"{name}: scanned={self.scanned} already_current={self.current} {verb}={self.rotated}"
            f" changed_meanwhile={self.changed_meanwhile} undecryptable={len(self.failed)}"
        )


class _BatchUndecryptableError(Exception):
    """Raised inside a batch transaction so it rolls back without writing anything."""


async def _column_exists(session: AsyncSession, col: EncryptedColumn) -> bool:
    row = await session.execute(
        text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = :t AND column_name = :c"
        ),
        {"t": col.table, "c": col.column},
    )
    return row.first() is not None


async def _rotate_batch(
    session: AsyncSession,
    col: EncryptedColumn,
    keyring: Keyring,
    rows: list[tuple[uuid.UUID, str, str]],
    report: ColumnReport,
    *,
    dry_run: bool,
) -> None:
    """Decrypt every row first; only if ALL open, rewrite the ones not under the current key."""
    pending: list[tuple[uuid.UUID, bytes, str, str]] = []  # pk, aad, old value, plaintext
    failed: list[uuid.UUID] = []
    for pk, aad_value, value in rows:
        aad = aad_value.encode()
        try:
            plaintext, key_index = keyring.decrypt_with_index(value, aad)
        except DecryptionError:
            failed.append(pk)
            continue
        if key_index == 0:
            report.current += 1
        else:
            pending.append((pk, aad, value, plaintext))
    if failed:
        report.failed.extend(failed)
        raise _BatchUndecryptableError

    # identifiers come only from the constant ENCRYPTED_COLUMNS registry, never from input
    update = text(
        f"UPDATE {col.table} SET {col.column} = :new WHERE {col.pk} = :pk AND {col.column} = :old"  # noqa: S608
    )
    reread = text(f"SELECT {col.column} FROM {col.table} WHERE {col.pk} = :pk")  # noqa: S608
    for pk, aad, old, plaintext in pending:
        if dry_run:
            report.rotated += 1
            continue
        new = keyring.encrypt(plaintext, aad)
        result = await session.execute(update, {"new": new, "pk": pk, "old": old})
        if result.rowcount != 1:  # type: ignore[attr-defined]
            report.changed_meanwhile += 1  # the app wrote a fresh value (current key) meanwhile
            continue
        stored = (await session.execute(reread, {"pk": pk})).scalar_one()
        check, key_index = keyring.decrypt_with_index(stored, aad)
        if key_index != 0 or check != plaintext:  # never commit a value we can't read back
            raise RuntimeError(f"{col.name} {pk}: re-encrypted value failed verification")
        report.rotated += 1


async def _rotate_column(
    col: EncryptedColumn, keyring: Keyring, batch_size: int, dry_run: bool
) -> ColumnReport:
    report = ColumnReport()
    async with db_session(DbContext.system()) as session:
        report.present = await _column_exists(session, col)
    if not report.present:
        return report
    select = text(
        f"SELECT {col.pk} AS row_pk, {col.aad_column}::text AS row_aad, {col.column} AS row_value "  # noqa: S608
        f"FROM {col.table} "
        f"WHERE {col.column} IS NOT NULL AND {col.pk} > :after ORDER BY {col.pk} LIMIT :n"
    )
    after = uuid.UUID(int=0)
    while True:
        try:
            async with db_session(DbContext.system()) as session:
                rows = [
                    (r[0], r[1], r[2])
                    for r in await session.execute(select, {"after": after, "n": batch_size})
                ]
                if not rows:
                    break
                after = rows[-1][0]
                report.scanned += len(rows)
                await _rotate_batch(session, col, keyring, rows, report, dry_run=dry_run)
        except _BatchUndecryptableError:
            continue  # rolled back; keep going so the operator sees every bad row in one run
        if len(rows) < batch_size:
            break
    return report


async def run(keyring: Keyring, *, batch_size: int = 500, dry_run: bool = False) -> int:
    """Rotate all columns; prints one line per column. Returns the process exit code."""
    reports = {}
    for col in ENCRYPTED_COLUMNS:
        reports[col.name] = report = await _rotate_column(col, keyring, batch_size, dry_run)
        print(report.line(col.name, dry_run))
        for pk in report.failed:
            print(f"  undecryptable: {col.name} row {pk}", file=sys.stderr)
    failed = sum(len(r.failed) for r in reports.values())
    if not dry_run:
        metadata = {
            name: f"scanned={r.scanned} rotated={r.rotated} already_current={r.current} "
            f"undecryptable={len(r.failed)}"
            for name, r in reports.items()
            if r.present
        }
        metadata["result"] = "failed" if failed else "ok"
        metadata["keys_configured"] = str(keyring.size)
        async with db_session(DbContext.system()) as session:
            await audit.record(
                session, actor="operator:cli", action="ops.encryption_key_rotated", metadata=metadata
            )
    if failed:
        print(
            f"FAILED: {failed} value(s) can't be decrypted with DATA_ENCRYPTION_KEY or any of "
            "DATA_ENCRYPTION_KEYS_PREVIOUS; their batches were left unchanged",
            file=sys.stderr,
        )
        return 1
    print("dry run: nothing was changed" if dry_run else "OK: every encrypted value is under the current key")
    return 0


async def _main(batch_size: int, dry_run: bool) -> int:
    try:
        return await run(get_settings().keyring, batch_size=batch_size, dry_run=dry_run)
    finally:
        await dispose_engine()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--dry-run", action="store_true", help="check and count only; write nothing")
    parser.add_argument("--batch-size", type=int, default=500, help="rows per transaction (default 500)")
    args = parser.parse_args()
    if not 1 <= args.batch_size <= 10_000:
        parser.error("--batch-size must be between 1 and 10000")
    return asyncio.run(_main(args.batch_size, args.dry_run))


if __name__ == "__main__":
    raise SystemExit(main())
