from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

import pytest

from securerelease.orchestrator import scan
from securerelease.scanners import zap
from securerelease.scanners.zap import ZapScanner, _container_url

SAMPLE = {
    "site": [{"alerts": [
        {"pluginid": "10038", "name": "CSP Header Not Set", "riskcode": "2", "confidence": "3", "cweid": "693",
         "desc": "<p>CSP is missing.</p>", "solution": "<p>Set a CSP.</p>",
         "reference": "<p>https://developer.mozilla.org/docs/CSP</p>",
         "instances": [{"uri": "http://host.docker.internal:3001/", "method": "GET", "param": "", "attack": ""}]},
        {"pluginid": "40018", "name": "SQL Injection", "riskcode": "3", "confidence": "2", "cweid": "89",
         "desc": "SQLi", "solution": "Use parameterized queries.", "reference": "",
         "instances": [{"uri": "http://host.docker.internal:3001/rest?q=1", "method": "GET", "param": "q", "attack": "'"}]},
    ]}],
}


def _proc(returncode=0, stdout="Total of 12 URLs"):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")


def test_alerts_are_normalized_and_mapped_back_to_original_host():
    findings = ZapScanner()._normalize(SAMPLE, _proc(), "http://localhost:3001", "Website", "baseline", False)
    by_id = {f.check_id: f for f in findings}
    assert by_id["ZAP-40018"].status == "FAIL" and by_id["ZAP-40018"].severity == "HIGH"
    assert by_id["ZAP-10038"].status == "WARN" and by_id["ZAP-10038"].severity == "MEDIUM"
    assert by_id["ZAP-10038"].asset == "http://localhost:3001/"
    assert "<p>" not in by_id["ZAP-10038"].summary
    assert by_id["ZAP-COVERAGE"].evidence["urls_seen"] == 12


def test_no_alerts_is_pass_with_limit_statement():
    findings = ZapScanner()._normalize({"site": []}, _proc(), "https://x.test", "Website", "baseline", False)
    assert [f.status for f in findings] == ["PASS"]
    assert "not mean" in findings[0].summary


def test_script_error_exit_is_not_a_clean_pass():
    findings = ZapScanner()._normalize({"site": []}, _proc(returncode=3), "https://x.test", "Website", "baseline", False)
    assert any(f.status == "ERROR" for f in findings)


def test_active_scan_requires_authorization(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("ZAP must not run without authorization"))
    findings = ZapScanner().scan("https://x.test", mode="active", authorized=False)
    assert findings[0].status == "NOT_TESTED" and findings[0].check_id == "ZAP-ACTIVE-NOT-AUTHORIZED"


def test_missing_docker_is_not_tested(monkeypatch):
    monkeypatch.setattr(zap.shutil, "which", lambda _n: None)
    findings = ZapScanner().scan("https://x.test")
    assert findings[0].check_id == "TOOL-ZAP-MISSING" and findings[0].status == "NOT_TESTED"


def test_loopback_urls_are_rewritten_for_the_container():
    assert _container_url("http://localhost:3001/a") == "http://host.docker.internal:3001/a"
    assert _container_url("https://example.com/a") == "https://example.com/a"


def test_api_scan_uses_spec_and_safe_mode_by_default(tmp_path):
    spec = tmp_path / "openapi.yaml"
    spec.write_text("openapi: 3.0.0\n")
    work = tmp_path / "work"
    work.mkdir()
    args, err = ZapScanner()._script_args("http://localhost:8000", "baseline", str(spec), False, 5, work)
    assert err is None and args[0] == "zap-api-scan.py" and "-S" in args and "openapi" in args
    assert (work / "spec.yaml").exists()
    active, _ = ZapScanner()._script_args("http://localhost:8000", "active", str(spec), True, 5, work)
    assert "-S" not in active


def test_missing_spec_is_an_error(tmp_path):
    _, err = ZapScanner()._script_args("http://localhost:8000", "baseline", str(tmp_path / "nope.yaml"), False, 5, tmp_path)
    assert err.status == "ERROR"


def test_dast_profile_validates_arguments():
    with pytest.raises(ValueError):
        scan(profile="dast")
    with pytest.raises(ValueError):
        scan(profile="dast", url="https://x.test", openapi_spec="a.yaml")
    with pytest.raises(ValueError):
        scan(profile="baseline", api_url="https://x.test", openapi_spec="a.yaml")


def test_sample_is_valid_json():
    json.dumps(SAMPLE)
