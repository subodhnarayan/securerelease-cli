from __future__ import annotations

import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from securerelease.models import Finding, ScanReport
from securerelease.scanners.gitleaks import GitleaksScanner
from securerelease.scanners.api_scanner import scan_api
from securerelease.scanners.http_baseline import TargetRejected, scan_url, validate_target
from securerelease.scanners.semgrep import SemgrepScanner
from securerelease.scanners.trivy import TrivyScanner
from securerelease.scanners.ui_browser import browser_status
from securerelease.scanners.ui_scanner import scan_ui
from securerelease.scanners.zap import ZapScanner, zap_status


def _version(executable: str) -> str:
    binary = shutil.which(executable)
    if not binary:
        return "not installed"
    try:
        result = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=5, check=False)
        line = (result.stdout or result.stderr).strip().splitlines()
        return line[0][:200] if line else "installed; version unavailable"
    except (OSError, subprocess.TimeoutExpired):
        return "installed; version unavailable"


def available_scanners() -> dict[str, str]:
    engines = {name: _version(name) for name in ("trivy", "gitleaks", "semgrep")}
    engines["zap"] = zap_status()
    engines["playwright"] = browser_status()
    return engines


def scan(
    *,
    profile: str,
    url: str | None = None,
    api_url: str | None = None,
    source: str | None = None,
    allow_private_targets: bool = False,
    openapi_spec: str | None = None,
    zap_mode: str = "baseline",
    authorized: bool = False,
    zap_minutes: int = 5,
    api_token_env: str | None = None,
    api_token_b_env: str | None = None,
    api_auth_header_env: str | None = None,
    ui_engine: str = "auto",
    ui_auth_header_env: str | None = None,
    ui_storage_state: str | None = None,
    ui_login_url: str | None = None,
    ui_user_env: str | None = None,
    ui_pass_env: str | None = None,
    max_pages: int = 25,
    max_requests: int = 300,
    allow_mutating: bool = False,
) -> ScanReport:
    if profile not in {"baseline", "repository", "full", "dast", "api", "ui"}:
        raise ValueError("Profile must be baseline, repository, full, dast, api, or ui.")
    if profile == "api":
        if not api_url:
            raise ValueError("The api profile requires --api-url.")
        if url or source:
            raise ValueError("The api profile accepts --api-url only. Use --profile full to combine URL, API, and source scans.")
    if profile == "ui":
        if not url:
            raise ValueError("The ui profile requires --url.")
        if api_url or source:
            raise ValueError("The ui profile accepts --url only. Use --profile full to combine URL, API, and source scans.")
    if ui_engine not in {"auto", "crawler", "browser"}:
        raise ValueError("--ui-engine must be auto, crawler, or browser.")
    if max_pages < 1 or max_pages > 500:
        raise ValueError("--max-pages must be between 1 and 500.")
    if max_requests < 10 or max_requests > 5000:
        raise ValueError("--max-requests must be between 10 and 5000.")
    if (api_token_b_env and not api_token_env):
        raise ValueError("--api-token-b-env requires --api-token-env.")
    if profile == "dast":
        if not (url or api_url):
            raise ValueError("The dast profile requires --url and/or --api-url.")
        if source:
            raise ValueError("The dast profile does not accept --source. Use --profile full for URL and source scans.")
    if openapi_spec and not api_url:
        raise ValueError("--openapi-spec requires --api-url.")
    if openapi_spec and profile not in {"dast", "api", "full"}:
        raise ValueError("--openapi-spec is only used by the dast, api, and full profiles.")
    if zap_mode not in {"baseline", "active"}:
        raise ValueError("--zap-mode must be baseline or active.")
    if zap_minutes < 1 or zap_minutes > 120:
        raise ValueError("--zap-minutes must be between 1 and 120.")
    if profile == "baseline" and not (url or api_url):
        raise ValueError("The baseline profile requires --url or --api-url.")
    if profile == "repository" and not source:
        source = "."
    if profile == "full" and not (url or api_url or source):
        raise ValueError("The full profile needs at least one of --url, --api-url or --source.")
    if profile == "repository" and (url or api_url):
        raise ValueError("The repository profile accepts --source only. Use --profile full to combine URL and source scans.")
    if profile == "baseline" and source:
        raise ValueError("The baseline profile does not accept --source. Use --profile full to combine URL and source scans.")

    targets: list[str] = []
    findings: list[Finding] = []
    report = ScanReport(profile=profile, targets=targets, scan_id=uuid.uuid4().hex[:12])
    report.tool_versions = {"SecureRelease": __import__("securerelease").__version__}

    urls: list[tuple[str, str]] = []
    if url:
        urls.append(("Website", url))
    if api_url:
        urls.append(("API", api_url))
    for label, target in urls:
        targets.append(target)
        if profile in {"api", "ui"}:
            continue  # the dedicated scanners below perform their own target validation
        findings.extend(scan_url(target, label=label, allow_private=allow_private_targets))
        if profile == "dast":
            findings.extend(_run_zap(target, label, report, allow_private_targets, openapi_spec if label == "API" else None,
                                     zap_mode, authorized, zap_minutes))

    if profile in {"ui", "full"} and url:
        ui_findings, ui_versions = scan_ui(
            url, allow_private=allow_private_targets, engine=ui_engine, authorized=authorized, max_pages=max_pages,
            max_requests=max_requests, auth_header_env=ui_auth_header_env, storage_state=ui_storage_state,
            login_url=ui_login_url, user_env=ui_user_env, pass_env=ui_pass_env,
        )
        findings.extend(ui_findings)
        report.tool_versions.update({f"ui:{k}": v for k, v in ui_versions.items()})
    if profile in {"api", "full"} and api_url:
        api_findings, api_versions = scan_api(
            api_url, allow_private=allow_private_targets, spec_source=openapi_spec, token_env=api_token_env,
            token_b_env=api_token_b_env, auth_header_env=api_auth_header_env, authorized=authorized,
            allow_mutating=allow_mutating, max_requests=max_requests,
        )
        findings.extend(api_findings)
        report.tool_versions.update({f"api:{k}": v for k, v in api_versions.items()})

    if source:
        source_path = Path(source).expanduser().resolve()
        targets.append(str(source_path))
        if not source_path.exists() or not source_path.is_dir():
            findings.append(Finding(
                check_id="REPOSITORY-PATH", title="Repository source path", status="ERROR", severity="INFO",
                source="securerelease", asset=str(source_path),
                summary="The source path does not exist or is not a directory.",
                remediation="Provide a directory containing the source files to scan.",
            ))
        else:
            scanners = [TrivyScanner(), GitleaksScanner(), SemgrepScanner()]
            for scanner in scanners:
                findings.extend(scanner.scan(source_path))
                if scanner.available():
                    report.tool_versions[scanner.name] = _version(scanner.executable)
                else:
                    report.tool_versions[scanner.name] = "not installed"
            report.notes.append(
                "Repository scans use optional external engines. NOT_TESTED findings indicate an engine was unavailable; install the engine and rerun."
            )

    if profile == "dast":
        report.notes.append(
            f"ZAP ran in '{zap_mode}' mode. Baseline mode is passive (spider plus response analysis); "
            "active mode sends attack payloads and requires --authorized. Authenticated areas and "
            "authorization logic (BOLA/IDOR) are not covered."
        )
    if profile in {"ui", "api", "full"} and (url or api_url):
        report.notes.append(
            "UI and API scanners are passive by default (GET/OPTIONS, same-origin, request-budgeted). "
            + ("Active probes (BOLA replay, fuzzing, rate-limit burst, reflection/open-redirect probes) ran because --authorized was set."
               if authorized else
               "Active probes (BOLA replay, fuzzing, rate-limit burst, reflection/open-redirect probes) were not run; add --authorized for an environment you own.")
            + (" Mutating methods were enabled by --allow-mutating." if allow_mutating else "")
        )
    if allow_private_targets:
        report.notes.append(
            "Private/local target opt-in was enabled. Use only for systems you own or are explicitly authorized to assess."
        )
    if profile not in {"api", "ui"}:
        report.notes.append(
            "URL baseline checks observe a small set of HTTP responses. They do not crawl an application, authenticate, prove authorization, or replace DAST/SAST review."
        )
    # Preserve first occurrence and drop exact duplicates produced by overlapping engines.
    findings = _deduplicate(findings)
    report.targets = targets
    report.findings = findings
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def _run_zap(target, label, report, allow_private, spec, mode, authorized, minutes) -> list[Finding]:
    try:
        validate_target(target, allow_private)
    except TargetRejected:
        return []  # scan_url already reported the policy rejection for this target
    scanner = ZapScanner()
    findings = scanner.scan(target, label=label, mode=mode, openapi_spec=spec, authorized=authorized, max_minutes=minutes)
    report.tool_versions["zap"] = zap_status()
    return findings


def _deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str, str]] = set()
    result: list[Finding] = []
    for finding in findings:
        key = (finding.source, finding.check_id, finding.asset, finding.title)
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result
