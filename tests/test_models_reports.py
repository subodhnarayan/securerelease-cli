import json

from securerelease.models import Finding, ScanReport
from securerelease.reports import as_json, as_sarif


def sample_finding(status="WARN", severity="MEDIUM"):
    return Finding(
        check_id="TEST-001", title="Example issue", status=status, severity=severity,
        source="test", asset="https://example.test", summary="Example evidence.",
        evidence={"header": "missing"}, remediation="Set the required header.",
    )


def test_scan_report_counts_all_statuses():
    report = ScanReport(profile="baseline", targets=["https://example.test"], findings=[
        sample_finding("WARN", "MEDIUM"), sample_finding("PASS", "INFO"),
    ], scan_id="test-id", finished_at="now")
    counts = report.summary()
    assert counts["WARN"] == 1
    assert counts["PASS"] == 1
    assert counts["FAIL"] == 0


def test_json_report_has_limitations_and_findings():
    report = ScanReport(profile="baseline", targets=[], findings=[sample_finding()], scan_id="test")
    output = json.loads(as_json(report))
    assert output["findings"][0]["check_id"] == "TEST-001"
    assert "not a penetration test" in output["disclaimer"]


def test_sarif_exports_only_actionable_results():
    report = ScanReport(profile="baseline", targets=[], findings=[
        sample_finding("WARN", "MEDIUM"), sample_finding("PASS", "INFO"),
    ], scan_id="test")
    data = json.loads(as_sarif(report))
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) == 1
    assert data["runs"][0]["results"][0]["ruleId"] == "TEST-001"


def test_sarif_includes_source_location_when_available():
    finding = Finding(
        check_id="SAST-1", title="Unsafe pattern", status="FAIL", severity="HIGH",
        source="semgrep", asset="src/app.py:7", summary="Example source finding.",
        evidence={"path": "src/app.py", "line": 7}, remediation="Review the code.",
    )
    report = ScanReport(profile="repository", targets=["."], findings=[finding], scan_id="test")
    data = json.loads(as_sarif(report))
    location = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "src/app.py"
    assert location["region"]["startLine"] == 7


def test_html_report_is_self_contained_and_escapes_content():
    from securerelease.reports import as_html

    evil = Finding(
        check_id="X-1", title="<script>alert(1)</script>", status="FAIL", severity="HIGH", source="securerelease_ui",
        asset="https://example.test/?a=<b>", summary="{{profile}} <img src=x onerror=alert(1)>",
        evidence={"note": "</pre><script>bad()</script>"}, remediation="Fix \"it\"",
    )
    report = ScanReport(profile="ui", targets=["https://example.test"], findings=[evil, sample_finding("PASS", "INFO")],
                        scan_id="abc123", finished_at="done", notes=["<b>note</b>"], tool_versions={"ui-engine": "built-in crawler"})
    page = as_html(report)
    assert page.startswith("<!doctype html>") and "{{" not in page.replace("{{profile}}", "")
    assert "<script>alert(1)</script>" not in page and "<img src=x" not in page and "</pre><script>bad()" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page and "{{profile}} &lt;img" in page
    assert "Action needed" in page and "UI scanner" in page and "built-in crawler" in page
    assert "http://" not in page.replace("https://example.test", "") and "<link " not in page


def test_html_report_flags_coverage_gaps_and_handles_empty_reports():
    from securerelease.reports import as_html

    gap = Finding("HTTP-CONNECTIVITY", "Connectivity", "NOT_TESTED", "INFO", "securerelease_api", "a", "timeout")
    assert "Incomplete coverage" in as_html(ScanReport(profile="api", targets=["a"], findings=[gap], scan_id="1"))
    assert "No checks were run" in as_html(ScanReport(profile="api", targets=[], scan_id="2"))
