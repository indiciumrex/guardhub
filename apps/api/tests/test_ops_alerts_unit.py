"""Admin operational alerts (Prompt 2 §2): the 5xx counter never breaks a request, and alert
mails carry counts and a link only."""

from __future__ import annotations

import uuid

from guardhub_api.opsalerts import counters
from guardhub_api.opsalerts.service import Mail, build_mail


class _BrokenRedis:
    def pipeline(self, transaction: bool = False) -> object:
        raise ConnectionError("redis is down")


class _Redis:
    def __init__(self, values: dict[str, int]) -> None:
        self.values = values

    async def mget(self, keys: list[str]) -> list[int | None]:
        return [self.values.get(k) for k in keys]


async def test_counting_never_raises() -> None:
    await counters.count_5xx(_BrokenRedis())  # type: ignore[arg-type]


async def test_errors_in_window_sums_the_minutes() -> None:
    now = 1_800_000_000.0
    m = int(now // 60)
    redis = _Redis(
        {f"{counters.PREFIX}{m}": 3, f"{counters.PREFIX}{m - 4}": 2, f"{counters.PREFIX}{m - 5}": 9}
    )
    assert await counters.errors_in_window(redis, 5, now) == 5  # type: ignore[arg-type]


def test_mail_has_counts_and_a_link_only() -> None:
    mail = Mail(alert_id=uuid.uuid4(), kind="scan_failures", value=7, threshold=5, escalation=False)
    en = build_mail(mail, "en")
    assert en.subject == "[GuardHub] Alert: Scan failures"
    assert "7" in en.text and "5" in en.text and en.text.rstrip().endswith("/admin/alerts")
    tr = build_mail(Mail(mail.alert_id, "worker_offline", 9, 5, escalation=True), "tr-TR")
    assert tr.subject.startswith("[GuardHub] Eskalasyon") and "Tarayıcı" in tr.subject
    assert "\n" not in tr.subject
