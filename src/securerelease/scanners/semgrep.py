from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from securerelease.models import Finding
from securerelease.scanners.base import RepositoryScanner


class SemgrepScanner(RepositoryScanner):
    name = "semgrep"
    executable = "semgrep"

    def available(self) -> bool:
        return shutil.which(self.executable) is not None

    def scan(self, source: Path) -> list[Finding]:
        binary = shutil.which(self.executable)
        if not binary:
            return [Finding(
                check_id="TOOL-SEMGREP-MISSING", title="Semgrep availability", status="NOT_TESTED",
                severity="INFO", source=self.name, asset=str(source),
                summary="Semgrep is not installed; source-code pattern analysis was not run.",
                remediation="Install Semgrep and configure the rule sources appropriate for your project. See https://semgrep.dev/docs/.",
            )]
        command = [binary, "scan", "--json", "--config", "auto", str(source)]
        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=300, check=False)
        except subprocess.TimeoutExpired:
            return [Finding("SEMGREP-TIMEOUT", "Semgrep scan", "ERROR", "INFO", self.name, str(source),
                            "Semgrep exceeded its 300-second execution limit.", remediation="Review repository size and scan configuration.")]
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return [Finding("SEMGREP-FAILED", "Semgrep scan", "ERROR", "INFO", self.name, str(source),
                            "Semgrep did not return a parseable JSON report.", {"exit_code": proc.returncode, "stderr": proc.stderr[-1200:]},
                            "Check Semgrep installation, network access to rule sources, and CLI compatibility.")]
        findings = []
        if proc.returncode != 0:
            findings.append(Finding(
                check_id="TOOL-SEMGREP-EXIT", title="Semgrep execution status", status="ERROR", severity="INFO",
                source=self.name, asset=str(source),
                summary="Semgrep returned a non-zero exit code; this scan must not be treated as clean.",
                evidence={"exit_code": proc.returncode, "stderr": proc.stderr[-1500:]},
                remediation="Inspect Semgrep stderr and resolve the execution/configuration issue before relying on the scan.",
            ))
        for record in data.get("results") or []:
            extra = record.get("extra") or {}
            metadata = extra.get("metadata") or {}
            severity_value = str(extra.get("severity") or metadata.get("security_severity_level") or "WARNING").upper()
            severity = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW", "CRITICAL": "CRITICAL"}.get(severity_value, "MEDIUM")
            path = str(record.get("path") or source)
            start = record.get("start") or {}
            rule_id = str(record.get("check_id") or "SEMGREP-FINDING")
            findings.append(Finding(
                check_id=f"SEMGREP-{rule_id}", title=str(extra.get("message") or rule_id)[:300],
                status="FAIL" if severity in {"CRITICAL", "HIGH"} else "WARN", severity=severity,
                source=self.name, asset=f"{path}:{start.get('line', '?')}",
                summary=str(extra.get("message") or "Source-code pattern reported by Semgrep.")[:1200],
                evidence={"rule_id": rule_id, "path": path, "line": start.get("line"),
                          "metadata": {k: v for k, v in metadata.items() if k not in {"references"}}},
                remediation="Review the code path and rule guidance; validate that the finding is applicable before making a release decision.",
                references=[str(r) for r in metadata.get("references", []) if isinstance(r, str)][:10],
            ))
        if not findings:
            findings.append(Finding(
                check_id="SEMGREP-NO-FINDINGS", title="Semgrep source scan", status="PASS", severity="INFO",
                source=self.name, asset=str(source),
                summary="Semgrep reported no findings for the configured rules. This is not proof of vulnerability-free code.",
                evidence={"exit_code": proc.returncode},
                remediation="Confirm the configured rules and language coverage match your repository.",
            ))
        return findings
