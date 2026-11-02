import json

from conftest import by_id

from securerelease.models import ScanReport
from securerelease.orchestrator import scan
from securerelease.reports import as_json, as_sarif
from securerelease.scanners.api_scanner import scan_api

ENV = {"TOKEN_ALICE": "token-alice", "TOKEN_BOB": "token-bob"}


def run(url, **kwargs):
    kwargs.setdefault("allow_private", True)
    kwargs.setdefault("env", ENV)
    findings, _ = scan_api(url, **kwargs)
    return findings, by_id(findings)


def test_spec_is_discovered_and_passive_findings_reported(mini_api_url):
    findings, found = run(mini_api_url)
    assert found["API-COVERAGE"].status == "WARN" and "9" in found["API-COVERAGE"].summary
    assert found["API-COVERAGE"].evidence["spec"].endswith("/openapi.json")
    assert found["API-UNAUTH-ACCESS"].status == "FAIL"
    assert [e["endpoint"] for e in found["API-UNAUTH-ACCESS"].evidence["exposed"]] == ["GET /admin/stats"]
    assert found["API-NOSNIFF"].status == "WARN"
    assert found["API-METHODS"].status == "WARN" and "TRACE" in found["API-METHODS"].summary
    assert found["API-TECH-DISCLOSURE"].status == "WARN"
    assert not any(f.status == "ERROR" for f in findings)


def test_active_tests_are_gated_behind_authorized(mini_api_url):
    _, found = run(mini_api_url, token_env="TOKEN_ALICE", token_b_env="TOKEN_BOB")
    for check in ("API-BOLA", "API-FUZZ", "API-RATE-LIMIT"):
        assert found[check].status == "NOT_TESTED" and "--authorized" in found[check].summary + found[check].remediation


def test_authorized_scan_finds_bola_and_cors_with_credentials(mini_api_url):
    _, found = run(mini_api_url, token_env="TOKEN_ALICE", token_b_env="TOKEN_BOB", authorized=True)
    bola = found["API-BOLA"]
    assert bola.status == "FAIL" and bola.severity == "HIGH"
    assert {e["endpoint"] for e in bola.evidence["vulnerable"]} == {"GET /users/{id}"}
    assert found["API-CORS"].status == "FAIL"
    assert found["API-AUTH-SCAN"].status == "PASS"


def test_bola_needs_two_users(mini_api_url):
    _, found = run(mini_api_url, token_env="TOKEN_ALICE", authorized=True)
    assert found["API-BOLA"].status == "NOT_TESTED"


def test_fuzzing_and_rate_limit(mini_api_url):
    _, found = run(mini_api_url, authorized=True)
    assert found["API-FUZZ-SERVER-ERROR"].status == "WARN"
    assert found["API-FUZZ-ERROR-DISCLOSURE"].status == "FAIL"
    assert found["API-RATE-LIMIT"].status == "WARN"


def test_mutating_and_delete_operations_are_skipped_by_default(mini_api_url):
    _, found = run(mini_api_url)
    reasons = {s["operation"]: s["reason"] for s in found["API-COVERAGE"].evidence["skipped"]}
    assert "use --allow-mutating" in reasons["POST /orders"] and "never sent" in reasons["DELETE /orders/{id}"]


def test_allow_mutating_enables_post_but_never_delete(mini_api_url):
    _, found = run(mini_api_url, allow_mutating=True)
    skipped = {s["operation"] for s in found["API-COVERAGE"].evidence["skipped"]}
    assert skipped == {"DELETE /orders/{id}"}


def test_spec_from_file_and_missing_file(mini_api_url, tmp_path):
    from pathlib import Path
    spec = Path(__file__).parent / "fixtures" / "mini_api" / "openapi.json"
    _, found = run(mini_api_url, spec_source=str(spec))
    assert found["API-COVERAGE"].evidence["operations_in_spec"] == 9
    findings, _ = scan_api(mini_api_url, allow_private=True, spec_source=str(tmp_path / "nope.json"))
    assert [f.check_id for f in findings] == ["API-SPEC-LOAD"] and findings[0].status == "ERROR"


def test_no_spec_probes_base_url_only():
    import httpx
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"ok": True}))
    findings, _ = scan_api("http://127.0.0.1:9", allow_private=True, transport=transport, env=ENV)
    found = by_id(findings)
    assert found["API-COVERAGE"].status == "WARN" and "No OpenAPI specification" in found["API-COVERAGE"].summary


def test_unreachable_api_is_a_coverage_gap_not_a_pass():
    findings, _ = scan_api("http://127.0.0.1:1", allow_private=True, env=ENV)
    assert [f.check_id for f in findings] == ["HTTP-CONNECTIVITY"] and findings[0].status == "NOT_TESTED"


def test_private_target_policy_applies():
    findings, _ = scan_api("http://127.0.0.1:8000")
    assert findings[0].check_id == "TARGET-POLICY" and findings[0].status == "NOT_TESTED"


def test_missing_token_variable_is_an_error():
    findings, _ = scan_api("http://127.0.0.1:8000", allow_private=True, token_env="NOPE", env={})
    assert findings[0].check_id == "API-AUTH-CONFIG" and findings[0].status == "ERROR"


def test_tokens_never_appear_in_reports(mini_api_url):
    report = scan(profile="api", api_url=mini_api_url, allow_private_targets=True, authorized=True)
    assert isinstance(report, ScanReport)
    import os
    os.environ.update(ENV)
    try:
        report = scan(profile="api", api_url=mini_api_url, allow_private_targets=True, authorized=True,
                      api_token_env="TOKEN_ALICE", api_token_b_env="TOKEN_BOB")
    finally:
        for key in ENV:
            os.environ.pop(key)
    for rendered in (as_json(report), as_sarif(report)):
        assert "token-alice" not in rendered and "token-bob" not in rendered
    assert json.loads(as_json(report))["profile"] == "api"
