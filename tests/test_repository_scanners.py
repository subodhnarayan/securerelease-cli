"""Integration tests that run the real scanner engines against seeded fixtures.

Each test is skipped only when the engine is not installed, so CI must install
Trivy, Gitleaks, and Semgrep to actually exercise these checks.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from securerelease.scanners.gitleaks import GitleaksScanner
from securerelease.scanners.semgrep import SemgrepScanner
from securerelease.scanners.trivy import TrivyScanner

FIXTURES = Path(__file__).parent / "fixtures"
VULNERABLE = FIXTURES / "vulnerable_repo"
CLEAN = FIXTURES / "clean_repo"
FAKE_SECRET = "ghp_R4nd0mFakeFixtureTokenValue0123456789ab"


def _need(executable: str) -> None:
    if shutil.which(executable) is None:
        pytest.skip(f"{executable} is not installed")


@pytest.fixture(scope="module")
def trivy_vulnerable():
    _need("trivy")
    return TrivyScanner().scan(VULNERABLE)


@pytest.fixture(scope="module")
def gitleaks_vulnerable():
    _need("gitleaks")
    return GitleaksScanner().scan(VULNERABLE)


@pytest.fixture(scope="module")
def semgrep_vulnerable(tmp_path_factory):
    _need("semgrep")
    # Semgrep's default ignore rules exclude directories named "tests".
    source = tmp_path_factory.mktemp("semgrep") / "vulnerable_repo"
    shutil.copytree(VULNERABLE, source)
    return SemgrepScanner().scan(source)


def _no_engine_errors(findings):
    assert not [f for f in findings if f.status in {"ERROR", "NOT_TESTED"}]


def test_trivy_detects_vulnerable_dependencies(trivy_vulnerable):
    _no_engine_errors(trivy_vulnerable)
    packages = {f.evidence["package"] for f in trivy_vulnerable if f.evidence and "package" in f.evidence}
    assert {"flask", "requests", "pyyaml"} <= packages
    assert any(f.severity == "CRITICAL" and f.status == "FAIL" for f in trivy_vulnerable)


def test_trivy_detects_dockerfile_misconfiguration(trivy_vulnerable):
    assert any(f.asset.endswith("Dockerfile") and f.check_id.startswith("TRIVY-DS-") for f in trivy_vulnerable)


def test_gitleaks_detects_seeded_secret_without_leaking_it(gitleaks_vulnerable):
    _no_engine_errors(gitleaks_vulnerable)
    hits = [f for f in gitleaks_vulnerable if f.status == "FAIL"]
    assert len(hits) == 1 and "settings.env" in hits[0].asset
    assert FAKE_SECRET not in repr(hits[0].to_dict())


def test_semgrep_detects_insecure_code_patterns(semgrep_vulnerable):
    _no_engine_errors(semgrep_vulnerable)
    rules = " ".join(f.check_id for f in semgrep_vulnerable)
    for expected in ("avoid-pyyaml-load", "subprocess-shell-true", "sqlalchemy-execute-raw-query", "eval-detected"):
        assert expected in rules


@pytest.mark.parametrize("scanner_cls,executable", [
    (TrivyScanner, "trivy"), (GitleaksScanner, "gitleaks"), (SemgrepScanner, "semgrep"),
])
def test_clean_repository_has_no_false_positives(scanner_cls, executable, tmp_path):
    _need(executable)
    source = tmp_path / "clean_repo"
    shutil.copytree(CLEAN, source)
    findings = scanner_cls().scan(source)
    assert [f.status for f in findings] == ["PASS"]


@pytest.mark.parametrize("scanner_cls,executable", [
    (TrivyScanner, "trivy"), (GitleaksScanner, "gitleaks"), (SemgrepScanner, "semgrep"),
])
def test_missing_engine_is_not_a_pass(scanner_cls, executable, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    findings = scanner_cls().scan(CLEAN)
    assert [f.status for f in findings] == ["NOT_TESTED"]
