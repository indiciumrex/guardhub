"""The admin invitation e-mail (Admin Panel gaps, 2026-11-26): the one-time link and its expiry,
in the inviting admin's language (texts: notifications.json, adminInviteMail)."""

from __future__ import annotations

from guardhub_api.alerts import render
from guardhub_api.alerts.delivery import send_email
from guardhub_api.alerts.render import AlertMessage

INVITE_HOURS = 72


def build(link: str, locale: str) -> AlertMessage:
    loc = "tr" if locale.startswith("tr") else "en"
    subject = render.one_line(render.text(loc, "adminInviteMail.subject"))
    body = render.text(loc, "adminInviteMail.body", hours=str(INVITE_HOURS))
    note = render.text(loc, "adminInviteMail.note")
    return AlertMessage(subject=subject, text=f"{body}\n\n{link}\n\n{note}\n", html="", slack="")


async def send(email: str, link: str, locale: str) -> None:
    await send_email(email, build(link, locale))
