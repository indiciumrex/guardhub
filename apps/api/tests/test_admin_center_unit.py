"""Admin control centre: pure parts (taxonomy, scorecards, lifecycle, the enable rule)."""

from __future__ import annotations

from guardhub_api.admin.center import lifecycle
from guardhub_api.findings.contract_gen import ACTIVE_CHECK_IDS, CHECK_IDS
from guardhub_api.findings.taxonomy import classify, known_checks
from guardhub_api.modules import registry, scorecards


def test_every_check_has_a_cwe_and_an_indicative_cvss() -> None:
    assert set(CHECK_IDS) <= known_checks()
    for check_id in CHECK_IDS:
        c = classify(check_id, "anything")
        assert c.cwe and all(x.startswith("CWE-") for x in c.cwe), check_id
        assert c.cvss_vector and c.cvss_vector.startswith("CVSS:3.1/AV:"), check_id
        assert c.cvss_score is not None and 0 <= c.cvss_score <= 10


def test_finding_specific_entries_and_advisory_ids() -> None:
    assert classify("exposed_env", "cloud_credentials_exposed").cwe[0] == "CWE-798"
    assert classify("active_sqli", "sql_injection").cwe == ["CWE-89"]
    c = classify(
        "dependency_vulns",
        "vulnerable_dependency_high",
        {"advisories": "GHSA-4w2v-q235-vp99, CVE-2024-12345 CVE-2024-12345", "package": "x"},
    )
    assert c.cves == ["CVE-2024-12345"] and c.advisories == ["GHSA-4w2v-q235-vp99"]
    assert classify("nope", "nope").cwe == []


def test_scorecards_give_gate_l_and_gate_m() -> None:
    m = scorecards.gate_for("active_xss", active=True)
    assert m.gate == "M" and m.measured and m.meets_gate and m.source
    assert m.false_positive_rate == 0.0
    passive = scorecards.gate_for("tls_cert", active=False)
    assert passive.gate == "L" and passive.measured and passive.meets_gate
    missing = scorecards.gate_for("not_a_check", active=False)
    assert not missing.measured and not missing.meets_gate and missing.source == ""


def test_lifecycle() -> None:
    assert lifecycle("done", None) == "completed"
    assert lifecycle("failed", "timeout") == "timed_out"
    assert lifecycle("failed", "target_unreachable") == "failed"
    assert lifecycle("cancelled", "cancelled") == "cancelled"
    assert lifecycle("queued", None) == "queued"


def test_active_checks_are_blocked_until_the_founder_approves() -> None:
    for key in ACTIVE_CHECK_IDS:
        assert registry.blocked_reason(key) == "active_testing_not_approved"
    assert registry.blocked_reason("tls_cert") is None  # measured, meets the gate
    assert registry.blocked_reason("ai") is None  # not a check: not gated here
