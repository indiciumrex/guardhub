"""Report tables and their exports (Admin Panel, Prompt 2 §3): masking, CSV and XLSX.

- Masking is always on for customer data: e-mail addresses and target hosts are shortened
  (`a***@e***.com`, `s***.com`) in every report, on screen and in every export.
- CSV: UTF-8 with BOM (Excel), and every cell that a spreadsheet would read as a formula
  (= + - @, tab, carriage return) is prefixed with an apostrophe (CSV injection, OWASP).
- XLSX: written with the standard library (zip + XML, inline strings), no dependency.
  Numbers are numbers; text is never a formula.
"""

from __future__ import annotations

import csv
import io
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit
from xml.sax.saxutils import escape

Cell = str | int | float | None


@dataclass(frozen=True, slots=True)
class Table:
    kind: str
    columns: list[str]
    rows: list[list[Cell]]
    days: int
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    truncated: bool = False


# ---- masking ----


def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    if not domain:
        return "***"
    name, _, tld = domain.rpartition(".")
    return f"{local[:1]}***@{(name or domain)[:1]}***.{tld or '***'}"


def mask_host(target: str) -> str:
    host = (urlsplit(target).hostname if "://" in target else target.split("/", maxsplit=1)[0]) or ""
    host = host.rstrip(".")
    if not host:
        return "***"
    labels = host.split(".")
    if len(labels) == 1:
        return f"{host[:1]}***"
    return f"{host[:1]}***.{labels[-1]}"


# ---- CSV ----

_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def _safe(cell: Cell) -> Cell:
    if isinstance(cell, str) and cell.startswith(_FORMULA_START):
        return "'" + cell
    return cell


def to_csv(table: Table) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(table.columns)
    for row in table.rows:
        w.writerow(["" if c is None else _safe(c) for c in row])
    return ("﻿" + buf.getvalue()).encode("utf-8")


# ---- XLSX (Office Open XML, minimal) ----


def _col(n: int) -> str:
    out = ""
    n += 1
    while n:
        n, r = divmod(n - 1, 26)
        out = chr(65 + r) + out
    return out


def _cell_xml(ref: str, value: Cell) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        value = int(value)
    if isinstance(value, int | float):
        return f'<c r="{ref}"><v>{value}</v></c>'
    text = escape(str(value)).replace('"', "&quot;")
    text = "".join(ch for ch in text if ch in "\t\n" or ord(ch) >= 32)  # XML 1.0 forbids controls
    return f'<c r="{ref}" t="inlineStr"><is><t xml:space="preserve">{text}</t></is></c>'


def to_xlsx(table: Table) -> bytes:
    rows_xml = []
    all_rows: list[list[Cell]] = [list(table.columns), *table.rows]
    for r, row in enumerate(all_rows, start=1):
        cells = "".join(_cell_xml(f"{_col(c)}{r}", v) for c, v in enumerate(row))
        rows_xml.append(f'<row r="{r}">{cells}</row>')
    sheet = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f"<sheetData>{''.join(rows_xml)}</sheetData></worksheet>"
    )
    files = {
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" '
            'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            "</Types>"
        ),
        "_rels/.rels": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="xl/workbook.xml"/></Relationships>'
        ),
        "xl/workbook.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            f'<sheets><sheet name="{escape(table.kind[:31])}" sheetId="1" r:id="rId1"/></sheets></workbook>'
        ),
        "xl/_rels/workbook.xml.rels": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
            'Target="worksheets/sheet1.xml"/></Relationships>'
        ),
        "xl/worksheets/sheet1.xml": sheet,
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in files.items():
            z.writestr(name, content)
    return buf.getvalue()
