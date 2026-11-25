"""Admin reports (Prompt 2 §3): masking, CSV injection, a valid XLSX, schedule timing."""

from __future__ import annotations

import csv
import io
import zipfile
from datetime import UTC, datetime
from xml.etree import ElementTree as ET

import pytest

from guardhub_api.reports.export import Table, mask_email, mask_host, to_csv, to_xlsx
from guardhub_api.reports.service import build_mail, due, summary

NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}


@pytest.mark.parametrize(
    ("email", "masked"),
    [
        ("alice@example.com", "a***@e***.com"),
        ("b@shop.example.co.uk", "b***@s***.uk"),
        ("broken", "***"),
    ],
)
def test_emails_are_masked(email: str, masked: str) -> None:
    assert mask_email(email) == masked


@pytest.mark.parametrize(
    ("target", "masked"),
    [
        ("https://shop.example.com/path?q=1", "s***.com"),
        ("https://localhost:8443", "l***"),
        ("example.org", "e***.org"),
        ("", "***"),
    ],
)
def test_hosts_are_masked(target: str, masked: str) -> None:
    assert mask_host(target) == masked


def _table() -> Table:
    return Table(
        "scans",
        ["target", "status", "score", "note"],
        [
            ["s***.com", "done", 87, '=HYPERLINK("http://evil")'],
            ["e***.org", "failed", None, "+1"],
            ["x***.io", "done", 99.5, "line\x01break & <tag>"],
        ],
        30,
    )


def test_csv_neutralises_formulas_and_opens_in_excel() -> None:
    raw = to_csv(_table())
    assert raw.startswith("﻿".encode())  # BOM: Excel reads UTF-8
    rows = list(csv.reader(io.StringIO(raw.decode("utf-8-sig"))))
    assert rows[0] == ["target", "status", "score", "note"]
    assert rows[1][3].startswith("'=")  # never a live formula
    assert rows[2][3] == "'+1"
    assert rows[2][2] == ""  # None is an empty cell


def test_xlsx_is_a_valid_workbook_with_typed_cells() -> None:
    data = to_xlsx(_table())
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        assert {"[Content_Types].xml", "xl/workbook.xml", "xl/worksheets/sheet1.xml"} <= set(z.namelist())
        sheet = ET.fromstring(z.read("xl/worksheets/sheet1.xml"))
    cells = sheet.findall(".//m:c", NS)
    by_ref = {c.get("r"): c for c in cells}
    assert by_ref["C2"].find("m:v", NS).text == "87"  # type: ignore[union-attr]
    assert by_ref["D2"].get("t") == "inlineStr"  # text, never a formula
    assert sheet.find(".//m:f", NS) is None
    note = by_ref["D4"].find("m:is/m:t", NS).text  # type: ignore[union-attr]
    assert note == "linebreak & <tag>"  # control character dropped, XML escaped and parsed back
    assert "B3" in by_ref and "C3" not in by_ref  # None leaves the cell out


@pytest.mark.parametrize(
    ("frequency", "now", "last", "expected"),
    [
        ("weekly", datetime(2026, 11, 30, 6, 5, tzinfo=UTC), None, True),  # a Monday
        ("weekly", datetime(2026, 12, 1, 6, 5, tzinfo=UTC), None, False),  # a Tuesday
        ("weekly", datetime(2026, 11, 30, 6, 5, tzinfo=UTC), datetime(2026, 11, 30, 6, 0, tzinfo=UTC), False),
        ("monthly", datetime(2026, 12, 1, 6, 5, tzinfo=UTC), datetime(2026, 11, 1, 6, 5, tzinfo=UTC), True),
        ("monthly", datetime(2026, 12, 2, 6, 5, tzinfo=UTC), None, False),
    ],
)
def test_schedule_timing(frequency: str, now: datetime, last: datetime | None, expected: bool) -> None:
    assert due(frequency, last, now) is expected


def test_summary_mail_has_counts_and_a_link_only() -> None:
    t = Table(
        "platform",
        [
            "date",
            "scans",
            "scans_done",
            "scans_failed",
            "scans_cancelled",
            "critical",
            "high",
            "medium",
            "low",
            "info",
            "new_users",
        ],
        [["2026-11-24", 3, 2, 1, 0, 1, 2, 0, 0, 0, 1], ["2026-11-25", 4, 4, 0, 0, 0, 1, 3, 0, 0, 0]],
        7,
    )
    totals = summary(t)
    assert totals == {"scans": 7, "scans_failed": 1, "critical": 1, "high": 3, "new_users": 1}
    mail = build_mail("weekly", totals, "tr")
    assert mail.subject == "[GuardHub] Haftalık platform raporu"
    assert "7" in mail.text and mail.text.rstrip().endswith("/admin/reports")
