"""Scanner event ingestion: consumes `gh:events` and persists scan results (ADR-0002).

The scanner returns raw technical findings. This layer validates each one against the shared
contract (packages/shared), keeps only known check/finding keys, takes the severity from the
catalog (deterministic, §2.6), encrypts evidence at rest, and computes the score.
Delivery is at-least-once, so every handler is idempotent (a finished scan is never rewritten).
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any  # JSON event payloads are untyped until validated

from pydantic import ValidationError
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.config import get_settings
from guardhub_api.db.models import Evidence, Finding, Scan
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.findings.catalog import text_key
from guardhub_api.findings.contract_gen import CHECK_FINDING_KEYS, RawFinding
from guardhub_api.findings.scoring import compute_score
from guardhub_api.health import counters
from guardhub_api.scans import repository

log = logging.getLogger("guardhub.ingest")

MAX_FINDINGS_PER_SCAN = 500
SCAN_FAILURE_CODES = {"target_unreachable", "target_blocked", "timeout", "internal"}


def _parse_time(value: object) -> datetime:
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            pass
    return datetime.now(UTC)


def validate_findings(raw: object, allowed_checks: set[str]) -> list[RawFinding]:
    """Keep only well-formed findings for checks this scan actually requested; dedupe by fingerprint."""
    if not isinstance(raw, list):
        return []
    out: dict[str, RawFinding] = {}
    for item in raw[:MAX_FINDINGS_PER_SCAN]:
        try:
            finding = RawFinding.model_validate(item)
        except ValidationError:
            log.warning("invalid_raw_finding_dropped")
            continue
        known = CHECK_FINDING_KEYS.get(finding.check_id, {})
        if finding.check_id not in allowed_checks or finding.finding_key not in known:
            log.warning(
                "unknown_finding_dropped", extra={"check_id": finding.check_id, "key": finding.finding_key}
            )
            continue
        # The catalog severity is authoritative: same finding → same severity → same score.
        finding = finding.model_copy(update={"severity": known[finding.finding_key]})
        out.setdefault(finding.fingerprint, finding)
    return list(out.values())


async def handle_event(redis: Redis, event: dict[str, Any]) -> None:
    if event.get("v") != 1:
        log.warning("unsupported_event_version", extra={"v": str(event.get("v"))})
        return
    try:
        scan_id = uuid.UUID(str(event.get("scan_id")))
    except ValueError:
        log.warning("event_without_valid_scan_id")
        return
    kind = event.get("type")
    at = _parse_time(event.get("at"))
    async with db_session(DbContext.system()) as session:
        scan = await repository.get(session, scan_id, for_update=True)
        if scan is None:
            log.warning("event_for_unknown_scan", extra={"scan_id": str(scan_id)})
            return
        if scan.status in ("done", "failed"):
            return  # idempotent: already final
        if kind == "scan.started":
            scan.status = "running"
            scan.started_at = scan.started_at or at
        elif kind == "scan.failed":
            error = str(event.get("error"))
            scan.status = "failed"
            scan.error = error if error in SCAN_FAILURE_CODES else "internal"
            scan.finished_at = at
        elif kind == "scan.completed":
            await _apply_completed(session, scan, event, at)
            await _record_check_health(redis, event.get("check_results"))
        else:
            log.warning("unknown_event_type", extra={"type": str(kind)})


async def _apply_completed(session: AsyncSession, scan: Scan, event: dict[str, Any], at: datetime) -> None:
    cipher = get_settings().keyring
    findings = validate_findings(event.get("findings"), set(scan.checks))
    for raw in findings:
        evidence_id = uuid.uuid4()
        finding = Finding(
            scan_id=scan.id,
            check_id=raw.check_id,
            finding_key=raw.finding_key,
            severity=raw.severity,
            title_key=text_key(raw.check_id, raw.finding_key, "title"),
            plain_summary=text_key(raw.check_id, raw.finding_key, "summary"),
            fix_guidance=text_key(raw.check_id, raw.finding_key, "fix"),
            params=dict(raw.params),
            fingerprint=raw.fingerprint,
            status="open",
        )
        evidence = Evidence(
            id=evidence_id,
            kind=raw.evidence.kind,
            location=raw.evidence.location,
            redacted_payload=cipher.encrypt(
                raw.evidence.redacted_payload, associated_data=str(evidence_id).encode()
            ),
        )
        await repository.add_finding_with_evidence(session, finding, evidence)
    scan.score = compute_score(f.severity for f in findings)
    scan.status = "done"
    scan.started_at = scan.started_at or at
    scan.finished_at = at


async def _record_check_health(redis: Redis, check_results: object) -> None:
    if not isinstance(check_results, list):
        return
    for item in check_results:
        if isinstance(item, dict) and isinstance(item.get("check_id"), str):
            await counters.record_check_result(redis, item["check_id"], ok=item.get("status") == "done")


def decode_payload(fields: dict[str, str]) -> dict[str, Any] | None:
    try:
        data = json.loads(fields.get("payload", ""))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None
