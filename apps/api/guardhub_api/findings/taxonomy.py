"""Standard identifiers for GuardHub findings (admin Findings & Risk view).

- CWE: the weakness class of each finding kind (MITRE CWE ids).
- CVSS: an INDICATIVE v3.1 base vector for the typical case of the finding kind, so findings can
  be sorted and compared with other tools. It is not a measurement of the customer's site: the
  site's real impact depends on what the page does. GuardHub's own severity (from the scanner's
  rules) stays the source of truth for the score.
- CVE: only where the scanner reported advisory ids (dependency_vulns, js_libraries).

Keys are check ids, or "check_id/finding_key" when one finding kind differs from its check.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from pydantic import BaseModel


@dataclass(frozen=True, slots=True)
class _Entry:
    cwe: tuple[int, ...]
    cvss: str  # CVSS:3.1 base vector (indicative)
    score: float  # its base score


# (CWE ids, indicative vector, base score)
_BY_CHECK: dict[str, _Entry] = {
    "exposed_env": _Entry((538, 200), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "exposed_env/cloud_credentials_exposed": _Entry(
        (798, 538), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8
    ),
    "exposed_files": _Entry((530, 538), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "exposed_files/source_map_exposed": _Entry((540,), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    "exposed_files/ds_store_exposed": _Entry((538,), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    "exposed_files/default_page_exposed": _Entry(
        (1188,), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0
    ),
    "security_headers": _Entry((693,), "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", 4.2),
    "security_headers/hsts_missing": _Entry((319,), "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", 3.7),
    "security_headers/clickjacking_unprotected": _Entry(
        (1021,), "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 4.3
    ),
    "security_headers/cookie_flags_missing": _Entry(
        (614, 1004), "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1
    ),
    "tls_cert": _Entry((295,), "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", 6.8),
    "tls_cert/https_unavailable": _Entry((319,), "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 8.1),
    "tls_cert/http_not_redirected": _Entry((319,), "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", 3.7),
    "tls_cert/cert_expiring_soon": _Entry((298,), "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", 3.7),
    "tls_cert/legacy_tls_supported": _Entry((327,), "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.1),
    "tls_config": _Entry((327,), "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.1),
    "tls_config/chain_incomplete": _Entry((295,), "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", 3.7),
    "tls_config/cert_weak_key": _Entry((326,), "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.3),
    "tls_depth": _Entry((295,), "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7),
    "open_admin": _Entry((284, 200), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", 8.2),
    "open_admin/debug_console_exposed": _Entry(
        (489, 94), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8
    ),
    "open_admin/admin_login_exposed": _Entry((1220,), "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7),
    "default_creds": _Entry((1188, 1392), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "info_leak": _Entry((200,), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    "info_leak/stack_trace_exposed": _Entry((209,), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    "info_leak/debug_mode_enabled": _Entry((489, 215), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "info_leak/directory_listing_enabled": _Entry(
        (548,), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3
    ),
    "http_hardening": _Entry((942, 693), "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N", 5.9),
    "dns_email": _Entry((290,), "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N", 3.1),
    "dns_email/open_resolver": _Entry((406,), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L", 5.8),
    "dns_email/zone_transfer_open": _Entry((200,), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    "dns_depth": _Entry((350, 290), "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N", 3.1),
    "subdomain_takeover": _Entry((350,), "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "dependency_vulns": _Entry((1395,), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", 7.3),
    "js_libraries": _Entry((1395,), "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "repo_secrets": _Entry((798,), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1),
    "repo_secrets/test_mode_secret": _Entry((798,), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    "js_secrets": _Entry((798, 540), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1),
    "js_secrets/test_secret_in_javascript": _Entry(
        (798,), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3
    ),
    "header_quality": _Entry((693,), "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
    "cookie_depth": _Entry((565, 1275), "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
    "content_signals": _Entry((319, 829), "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", 3.7),
    "content_signals/sri_missing": _Entry((353, 829), "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N", 4.7),
    "active_xss": _Entry((79,), "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "active_sqli": _Entry((89,), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "active_redirect": _Entry((601,), "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "active_cors": _Entry((942, 346), "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", 6.5),
    "active_ssrf": _Entry((918,), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N", 7.2),
    "active_idor": _Entry((639, 284), "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
}

_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
_GHSA = re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b")


class Classification(BaseModel):
    cwe: list[str]  # "CWE-79"
    cvss_vector: str | None  # indicative CVSS v3.1 base vector (the typical case)
    cvss_score: float | None
    cves: list[str]  # CVE ids the scanner reported (dependency advisories), else empty
    advisories: list[str]  # other advisory ids (GHSA)


def classify(check_id: str, finding_key: str, params: dict[str, str] | None = None) -> Classification:
    entry = _BY_CHECK.get(f"{check_id}/{finding_key}") or _BY_CHECK.get(check_id)
    text = " ".join((params or {}).values())
    cves = sorted(set(_CVE.findall(text)))
    ghsa = sorted(set(_GHSA.findall(text)))
    if entry is None:
        return Classification(cwe=[], cvss_vector=None, cvss_score=None, cves=cves, advisories=ghsa)
    return Classification(
        cwe=[f"CWE-{n}" for n in entry.cwe],
        cvss_vector=entry.cvss,
        cvss_score=entry.score,
        cves=cves,
        advisories=ghsa,
    )


def known_checks() -> set[str]:
    return {k.split("/", 1)[0] for k in _BY_CHECK}
