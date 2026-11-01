from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from securerelease.models import Finding
from securerelease.scanners.base import RepositoryScanner


class TrivyScanner(RepositoryScanner):
    name = "trivy"
    executable = "trivy"

    def available(self) -> bool:
        return shutil.which(self.executable) is not None

    def scan(self, source: Path) -> list[Finding]:
        binary = shutil.which(self.executable)
        if not binary:
            return [Finding(
                check_id="TOOL-TRIVY-MISSING", title="Trivy availability", status="NOT_TESTED",
                severity="INFO", source=self.name, asset=str(source),
                summary="Trivy is not installed; dependency, secret, and misconfiguration checks from this engine were not run.",
                remediation="Install Trivy and rerun the repository scan. See https://trivy.dev/.",
            )]
        command = [binary, "fs", "--format", "json", "--scanners", "vuln,misconfig,secret", "--timeout", "5m", str(source)]
        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=330, check=False)
        except subprocess.TimeoutExpired:
            return [Finding("TOOL-TRIVY-TIMEOUT", "Trivy scan", "ERROR", "INFO", self.name, str(source),
                            "Trivy exceeded its 330-second execution limit.", remediation="Review repository size and rerun with an appropriate resource budget.")]
        if not proc.stdout.strip():
            return [Finding("TOOL-TRIVY-FAILED", "Trivy scan", "ERROR", "INFO", self.name, str(source),
                            "Trivy did not return a JSON report.", {"exit_code": proc.returncode, "stderr": proc.stderr[-1500:]},
                            "Check the installed Trivy version and run the command locally to diagnose the failure.")]
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return [Finding("TOOL-TRIVY-INVALID-JSON", "Trivy scan", "ERROR", "INFO", self.name, str(source),
                            "Trivy output was not valid JSON.", {"exit_code": proc.returncode, "stderr": proc.stderr[-1000:]},
                            "Check Trivy compatibility and output format.")]
        findings: list[Finding] = []
        if proc.returncode != 0:
            findings.append(Finding(
                check_id="TOOL-TRIVY-EXIT", title="Trivy execution status", status="ERROR", severity="INFO",
                source=self.name, asset=str(source),
                summary="Trivy returned a non-zero exit code; any parsed findings are retained, but this run must not be treated as a clean scan.",
                evidence={"exit_code": proc.returncode, "stderr": proc.stderr[-1500:]},
                remediation="Inspect Trivy stderr and resolve the execution error before relying on this scan result.",
            ))
        for result in data.get("Results") or []:
            target = str(result.get("Target") or source)
            for item in result.get("Vulnerabilities") or []:
                vuln_id = str(item.get("VulnerabilityID") or "UNKNOWN-VULNERABILITY")
                severity = _severity(item.get("Severity"))
                fixed = item.get("FixedVersion")
                pkg = item.get("PkgName") or "unknown package"
                installed = item.get("InstalledVersion")
                findings.append(Finding(
                    check_id=f"TRIVY-{vuln_id}", title=str(item.get("Title") or vuln_id),
                    status="FAIL" if severity in {"CRITICAL", "HIGH"} else "WARN",
                    severity=severity, source=self.name, asset=f"{target}:{pkg}",
                    summary=(str(item.get("Description") or "Known package vulnerability reported by Trivy.")[:1600]),
                    evidence={"vulnerability_id": vuln_id, "package": pkg, "installed_version": installed,
                              "fixed_version": fixed, "target": target},
                    remediation=(f"Upgrade {pkg} to {fixed}." if fixed else
                                 "Review the advisory and determine whether an upgrade or mitigation is available."),
                    references=[str(item.get("PrimaryURL"))] if item.get("PrimaryURL") else [],
                ))
            for item in result.get("Misconfigurations") or []:
                misconfig_id = str(item.get("ID") or "UNKNOWN-MISCONFIG")
                severity = _severity(item.get("Severity"))
                findings.append(Finding(
                    check_id=f"TRIVY-{misconfig_id}", title=str(item.get("Title") or misconfig_id),
                    status="FAIL" if severity in {"CRITICAL", "HIGH"} else "WARN",
                    severity=severity, source=self.name, asset=target,
                    summary=str(item.get("Message") or item.get("Description") or "Misconfiguration reported by Trivy.")[:1200],
                    evidence={"id": misconfig_id, "type": item.get("Type"), "target": target,
                              "resource": (item.get("CauseMetadata") or {}).get("Resource")},
                    remediation=str(item.get("Resolution") or "Review the finding and apply the scanner's recommended configuration fix."),
                    references=[str(item.get("PrimaryURL"))] if item.get("PrimaryURL") else [],
                ))
            for item in result.get("Secrets") or []:
                rule_id = str(item.get("RuleID") or "SECRET-FOUND")
                title = str(item.get("Title") or "Potential secret detected")
                findings.append(Finding(
                    check_id=f"TRIVY-{rule_id}", title=title, status="FAIL", severity="HIGH",
                    source=self.name, asset=target,
                    summary="Trivy reported a potential secret. Secret values are intentionally omitted from this report.",
                    evidence={"rule_id": rule_id, "category": item.get("Category"), "target": target,
                              "start_line": item.get("StartLine"), "end_line": item.get("EndLine")},
                    remediation="Verify the finding without exposing the secret in logs, revoke/rotate it if valid, and remove it from the repository and history.",
                ))
        if not findings:
            findings.append(Finding(
                check_id="TRIVY-NO-FINDINGS", title="Trivy repository scan", status="PASS", severity="INFO",
                source=self.name, asset=str(source),
                summary="Trivy reported no findings in the categories enabled for this scan. This does not mean the repository is fully secure.",
                evidence={"scanners": ["vuln", "misconfig", "secret"], "exit_code": proc.returncode},
                remediation="Review coverage and run other appropriate checks, including source-code analysis and runtime testing.",
            ))
        return findings


def _severity(value: Any) -> str:
    val = str(value or "UNKNOWN").upper()
    return val if val in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} else "UNKNOWN"
