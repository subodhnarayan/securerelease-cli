from types import SimpleNamespace

from securerelease.cli import _exit_code
from securerelease.models import Finding


def f(check_id, status, severity="INFO"):
    return Finding(check_id=check_id, title=check_id, status=status, severity=severity,
                   source="test", asset="test", summary="summary")


def report(*findings):
    return SimpleNamespace(findings=list(findings))


def test_missing_required_scanner_does_not_pass_ci_by_default():
    assert _exit_code(report(f("TOOL-TRIVY-MISSING", "NOT_TESTED")), {"HIGH", "CRITICAL"}, False) == 2


def test_missing_scanner_can_be_report_only_when_explicitly_requested():
    assert _exit_code(report(f("TOOL-TRIVY-MISSING", "NOT_TESTED")), {"HIGH", "CRITICAL"}, True) == 0


def test_high_failure_blocks_but_low_warning_does_not():
    assert _exit_code(report(f("HTTP-HTTPS", "FAIL", "HIGH")), {"HIGH", "CRITICAL"}, False) == 1
    assert _exit_code(report(f("HTTP-CSP", "WARN", "MEDIUM")), {"HIGH", "CRITICAL"}, False) == 0
    assert _exit_code(report(f("TRIVY-CVE", "WARN", "MEDIUM")), {"MEDIUM", "HIGH", "CRITICAL"}, False) == 1


def test_target_policy_or_connectivity_gap_does_not_pass_ci():
    assert _exit_code(report(f("TARGET-POLICY", "NOT_TESTED")), {"HIGH", "CRITICAL"}, False) == 2
    assert _exit_code(report(f("HTTP-CONNECTIVITY", "NOT_TESTED")), {"HIGH", "CRITICAL"}, False) == 2


def test_report_only_mode_still_fails_on_scanner_execution_error():
    assert _exit_code(report(f("TOOL-TRIVY-FAILED", "ERROR")), {"HIGH", "CRITICAL"}, True) == 2
