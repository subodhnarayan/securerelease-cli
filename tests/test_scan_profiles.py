import pytest

from securerelease.cli import _exit_code, main
from securerelease.models import Finding
from securerelease.orchestrator import scan


def test_profile_argument_validation():
    with pytest.raises(ValueError):
        scan(profile="api")
    with pytest.raises(ValueError):
        scan(profile="api", api_url="https://x.test", url="https://y.test")
    with pytest.raises(ValueError):
        scan(profile="ui")
    with pytest.raises(ValueError):
        scan(profile="ui", url="https://x.test", source=".")
    with pytest.raises(ValueError):
        scan(profile="ui", url="https://x.test", ui_engine="selenium")
    with pytest.raises(ValueError):
        scan(profile="api", api_url="https://x.test", api_token_b_env="B")
    with pytest.raises(ValueError):
        scan(profile="api", api_url="https://x.test", max_requests=1)


def test_cli_api_scan_blocks_on_high_findings(mini_api_url, capsys):
    code = main(["api-scan", "--api-url", mini_api_url, "--allow-private-targets", "--format", "json"])
    assert code == 1
    assert '"profile": "api"' in capsys.readouterr().out


def test_cli_ui_scan_report_only_mode(mini_ui_url, capsys):
    code = main(["ui-scan", "--url", mini_ui_url, "--allow-private-targets", "--ui-engine", "crawler", "--no-fail-on-findings"])
    assert code == 0
    assert "UI: Crawl coverage" in capsys.readouterr().out


def test_cli_private_target_without_opt_in_is_exit_2(mini_api_url):
    assert main(["api-scan", "--api-url", mini_api_url]) == 2


def test_full_profile_runs_ui_and_api(mini_ui_url, mini_api_url):
    report = scan(profile="full", url=mini_ui_url, api_url=mini_api_url, source=".", allow_private_targets=True,
                  ui_engine="crawler")
    sources = {f.source for f in report.findings}
    assert {"securerelease_ui", "securerelease_api", "native_http_checks"} <= sources


def test_missing_browser_engine_fails_ci_by_default():
    finding = Finding("TOOL-PLAYWRIGHT-MISSING", "t", "NOT_TESTED", "INFO", "securerelease_ui", "a", "s")
    report = type("R", (), {"findings": [finding]})()
    assert _exit_code(report, {"HIGH"}, False) == 2
    assert _exit_code(report, {"HIGH"}, True) == 0
