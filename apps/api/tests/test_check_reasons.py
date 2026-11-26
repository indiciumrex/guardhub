"""Why a check could not finish (final prompt item 4): the scanner's reason code is kept."""

from guardhub_api.scans.ingest import SAFE_STOP_REASONS, failed_check_reasons


def test_reasons_for_failed_checks_only_with_a_fallback_for_missing_results() -> None:
    results = [
        {"check_id": "tls_cert", "status": "done", "error": None},
        {"check_id": "exposed_files", "status": "failed", "error": "budget_exceeded"},
        {"check_id": "dns_email", "status": "failed", "error": "target_unreachable"},
    ]
    reasons = failed_check_reasons(results, ["exposed_files", "dns_email", "js_libraries"])
    assert reasons == {
        "exposed_files": "budget_exceeded",
        "dns_email": "target_unreachable",
        "js_libraries": "no_result",  # requested, but the scanner sent no result
    }


def test_an_unexpected_code_is_never_stored_verbatim() -> None:
    results = [
        {"check_id": "a", "status": "failed", "error": "<script>"},
        {"check_id": "b", "status": "failed", "error": None},
        {"check_id": "c", "status": "failed", "error": "x" * 80},
    ]
    assert failed_check_reasons(results, ["a", "b", "c"]) == {
        "a": "internal",
        "b": "internal",
        "c": "internal",
    }
    assert failed_check_reasons("garbage", ["a"]) == {"a": "no_result"}


def test_safe_stops_are_the_do_no_harm_reasons() -> None:
    assert {"budget_exceeded", "target_stressed"} <= SAFE_STOP_REASONS
    assert "internal" not in SAFE_STOP_REASONS and "timeout" not in SAFE_STOP_REASONS
