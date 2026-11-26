"""The admin invitation e-mail: the one-time link, the expiry, en and tr, a one-line subject."""

from __future__ import annotations

from guardhub_api.admin import invite_mail

LINK = "https://guardhub.dev/account/admin-invite?token=ghi_abc"


def test_english_and_turkish() -> None:
    en = invite_mail.build(LINK, "en")
    assert en.subject == "[GuardHub] You are invited to the admin console"
    assert LINK in en.text
    assert "72 hours" in en.text
    assert "two-factor" in en.text
    tr = invite_mail.build(LINK, "tr-TR")
    assert tr.subject.startswith("[GuardHub] Yönetim konsoluna")
    assert LINK in tr.text
    assert "72 saat" in tr.text
    assert "\n" not in en.subject
    assert "\n" not in tr.subject
