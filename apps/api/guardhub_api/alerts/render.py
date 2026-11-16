"""Alert message rendering (docs/architecture.md §8.4, GUARDHUB_STANDARDS §8.1 brand, §7.5 i18n).

Texts come ONLY from packages/shared/i18n/<locale>/notifications.json (per-key fallback to `en`).
One message is built as a list of blocks and rendered three ways: plain text and simple HTML for
e-mail (GuardHub brand + "Powered by HKSolutions"), and Slack mrkdwn. Every dynamic value is
escaped for its format (HTML entities; Slack's `& < >`), and subjects are forced to one line.
Alerts list title + severity + one-line summary only: never evidence.
"""

from __future__ import annotations

import html
import json
import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from guardhub_api.common.request_meta import DEFAULT_LOCALE, SUPPORTED_LOCALES
from guardhub_api.config import get_settings
from guardhub_api.findings.catalog import render_template

log = logging.getLogger("guardhub.alerts.render")

MAX_ITEMS_PER_LIST = 10
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")

NAVY = "#0B2545"
TEAL = "#0F766E"
SLATE = "#F8FAFC"
MUTED = "#475569"
FONT_STACK = "system-ui,-apple-system,Segoe UI,Roboto,sans-serif"


@dataclass(frozen=True, slots=True)
class AlertItem:
    severity: str
    title: str
    summary: str


@dataclass(frozen=True, slots=True)
class AlertMessage:
    subject: str
    text: str
    html: str
    slack: str


# ---- catalog ----


def _flatten(obj: object, prefix: str = "") -> dict[str, str]:
    out: dict[str, str] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(_flatten(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(obj, str):
        out[prefix] = obj
    return out


def _load(shared_dir: Path, locale: str) -> dict[str, str]:
    path = shared_dir / "i18n" / locale / "notifications.json"
    if not path.exists():
        return {}
    try:
        return _flatten(json.loads(path.read_text(encoding="utf-8")))
    except json.JSONDecodeError:
        log.exception("invalid_i18n_file", extra={"path": str(path)})
        return {}


@lru_cache(maxsize=1)
def _catalog() -> dict[str, dict[str, str]]:
    shared = get_settings().shared_dir
    return {loc: _load(shared, loc) for loc in SUPPORTED_LOCALES}


def reload_texts() -> None:
    _catalog.cache_clear()


def text(locale: str, key: str, **params: str) -> str:
    template = _catalog().get(locale, {}).get(key) or _catalog()[DEFAULT_LOCALE].get(key)
    if template is None:
        log.error("missing_notification_text", extra={"key": key})
        template = f"[{key}]"
    return render_template(template, params)


def one_line(value: str, limit: int = 200) -> str:
    """No control characters (header / mrkdwn injection), bounded length."""
    cleaned = _CONTROL.sub(" ", value).strip()
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"


def slack_escape(value: str) -> str:
    """Slack's required escaping: stops `<!channel>` mentions and `<url|label>` link injection."""
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ---- blocks ----


@dataclass(frozen=True, slots=True)
class _Para:
    text: str
    muted: bool = False


@dataclass(frozen=True, slots=True)
class _Heading:
    text: str


@dataclass(frozen=True, slots=True)
class _Items:
    items: tuple[AlertItem, ...]
    more: str | None


@dataclass(frozen=True, slots=True)
class _Cta:
    label: str
    url: str


_Block = _Para | _Heading | _Items | _Cta


def _items_block(locale: str, items: Sequence[AlertItem]) -> _Items:
    shown = tuple(items[:MAX_ITEMS_PER_LIST])
    hidden = len(items) - len(shown)
    return _Items(shown, text(locale, "common.more", count=str(hidden)) if hidden > 0 else None)


def _severity(locale: str, severity: str) -> str:
    return text(locale, f"severity.{severity}")


def _render_text(locale: str, blocks: Sequence[_Block]) -> str:
    lines: list[str] = [text(locale, "common.greeting"), ""]
    for b in blocks:
        if isinstance(b, _Para):
            lines += [b.text, ""]
        elif isinstance(b, _Heading):
            lines += [b.text, "-" * len(b.text)]
        elif isinstance(b, _Items):
            for i in b.items:
                lines.append(
                    f"- [{_severity(locale, i.severity)}] {one_line(i.title)}: {one_line(i.summary, 300)}"
                )
            if b.more:
                lines.append(b.more)
            lines.append("")
        else:
            lines += [f"{b.label}: {b.url}", ""]
    lines += ["--", f"{text(locale, 'brand.name')} · {text(locale, 'brand.powered_by')}"]
    return "\n".join(lines) + "\n"


def _render_html(locale: str, subject: str, blocks: Sequence[_Block]) -> str:
    e = html.escape
    parts: list[str] = []
    for b in blocks:
        if isinstance(b, _Para):
            color = MUTED if b.muted else NAVY
            size = "13px" if b.muted else "15px"
            parts.append(
                f'<p style="margin:0 0 14px;color:{color};font-size:{size};line-height:1.5">{e(b.text)}</p>'
            )
        elif isinstance(b, _Heading):
            parts.append(f'<h2 style="margin:18px 0 8px;color:{NAVY};font-size:16px">{e(b.text)}</h2>')
        elif isinstance(b, _Items):
            rows = "".join(
                f'<li style="margin:0 0 8px"><strong>[{e(_severity(locale, i.severity))}] '
                f"{e(one_line(i.title))}</strong><br>"
                f'<span style="color:{MUTED}">{e(one_line(i.summary, 300))}</span></li>'
                for i in b.items
            )
            more = f'<p style="margin:0 0 14px;color:{MUTED}">{e(b.more)}</p>' if b.more else ""
            parts.append(f'<ul style="margin:0 0 14px;padding-left:20px;color:{NAVY}">{rows}</ul>{more}')
        else:
            parts.append(
                f'<p style="margin:18px 0"><a href="{e(b.url, quote=True)}" '
                f'style="background:{TEAL};color:#ffffff;padding:10px 16px;border-radius:6px;'
                f'text-decoration:none;display:inline-block">{e(b.label)}</a></p>'
            )
    lang = e(locale, quote=True)
    return (
        f'<!doctype html><html lang="{lang}"><head><meta charset="utf-8">'
        f'<meta name="viewport" content="width=device-width"><title>{e(subject)}</title></head>'
        f'<body style="margin:0;background:{SLATE};font-family:{FONT_STACK}">'
        f'<div style="max-width:600px;margin:0 auto;padding:24px 16px">'
        f'<div style="font-size:20px;font-weight:700;margin-bottom:16px">'
        f'<span style="color:{NAVY}">Guard</span><span style="color:{TEAL}">Hub</span></div>'
        f'<div style="background:#ffffff;border-radius:8px;padding:24px;border:1px solid #e2e8f0">'
        f'<p style="margin:0 0 14px;color:{NAVY};font-size:15px">{e(text(locale, "common.greeting"))}</p>'
        f"{''.join(parts)}</div>"
        f'<p style="margin:16px 0 0;color:{MUTED};font-size:12px">{e(text(locale, "brand.tagline"))}<br>'
        f"{e(text(locale, 'brand.powered_by'))}</p>"
        f"</div></body></html>"
    )


def _render_slack(locale: str, subject: str, blocks: Sequence[_Block]) -> str:
    s = slack_escape
    lines: list[str] = [f"*{s(subject)}*"]
    for b in blocks:
        if isinstance(b, _Para):
            lines.append(f"_{s(b.text)}_" if b.muted else s(b.text))
        elif isinstance(b, _Heading):
            lines.append(f"*{s(b.text)}*")
        elif isinstance(b, _Items):
            lines += [
                f"• [{s(_severity(locale, i.severity))}] {s(one_line(i.title))}: "
                f"{s(one_line(i.summary, 300))}"
                for i in b.items
            ]
            if b.more:
                lines.append(s(b.more))
        else:
            lines.append(f"<{s(b.url)}|{s(b.label)}>")
    lines.append(f"_{s(text(locale, 'brand.name'))} · {s(text(locale, 'brand.powered_by'))}_")
    return "\n".join(lines)


def _message(locale: str, subject: str, blocks: Sequence[_Block]) -> AlertMessage:
    subject = one_line(subject, 180)
    return AlertMessage(
        subject=subject,
        text=_render_text(locale, blocks),
        html=_render_html(locale, subject, blocks),
        slack=_render_slack(locale, subject, blocks),
    )


def _score_line(locale: str, score: int | None, base_score: int | None) -> list[_Block]:
    if score is None or base_score is None:
        return []
    return [_Para(text(locale, "common.score", score=str(score), base_score=str(base_score)))]


# ---- public builders ----


def change_alert(
    locale: str,
    *,
    project: str,
    target: str,
    link: str,
    new: Sequence[AlertItem],
    regressed: Sequence[AlertItem],
    fixed_count: int,
    score: int | None,
    base_score: int | None,
) -> AlertMessage:
    blocks: list[_Block] = [
        _Para(text(locale, "change.intro", target=target)),
        _Para(text(locale, "common.site", target=target)),
        *_score_line(locale, score, base_score),
    ]
    if new:
        blocks += [_Heading(text(locale, "change.new_heading")), _items_block(locale, new)]
    if regressed:
        blocks += [_Heading(text(locale, "change.regressed_heading")), _items_block(locale, regressed)]
    if fixed_count:
        blocks.append(_Para(text(locale, "change.fixed_line", count=str(fixed_count))))
    blocks += [_Cta(text(locale, "change.cta"), link), _Para(text(locale, "common.footer"), muted=True)]
    return _message(locale, text(locale, "change.subject", project=one_line(project, 120)), blocks)


def fixed_alert(
    locale: str,
    *,
    project: str,
    target: str,
    link: str,
    fixed: Sequence[AlertItem],
    score: int | None,
    base_score: int | None,
) -> AlertMessage:
    blocks: list[_Block] = [
        _Para(text(locale, "fixed.intro", target=target)),
        *_score_line(locale, score, base_score),
        _Heading(text(locale, "fixed.heading")),
        _items_block(locale, fixed),
        _Cta(text(locale, "fixed.cta"), link),
        _Para(text(locale, "common.footer"), muted=True),
    ]
    return _message(locale, text(locale, "fixed.subject", project=one_line(project, 120)), blocks)


def paused_alert(locale: str, *, project: str, target: str, link: str) -> AlertMessage:
    blocks: list[_Block] = [
        _Para(text(locale, "paused.intro", target=target)),
        _Para(text(locale, "paused.reason")),
        _Para(text(locale, "paused.action")),
        _Cta(text(locale, "paused.cta"), link),
        _Para(text(locale, "common.footer"), muted=True),
    ]
    return _message(locale, text(locale, "paused.subject", project=one_line(project, 120)), blocks)


def channel_check_alert(locale: str) -> AlertMessage:
    """The message sent by "send a test notification"."""
    blocks: list[_Block] = [
        _Para(text(locale, "test.intro")),
        _Para(text(locale, "test.detail")),
        _Para(text(locale, "common.footer"), muted=True),
    ]
    return _message(locale, text(locale, "test.subject"), blocks)
