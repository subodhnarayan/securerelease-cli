from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from securerelease.models import Finding
from securerelease.scanners.base import RepositoryScanner


class GitleaksScanner(RepositoryScanner):
    name = "gitleaks"
    executable = "gitleaks"

    def available(self) -> bool:
        return shutil.which(self.executable) is not None

    def scan(self, source: Path) -> list[Finding]:
        binary = shutil.which(self.executable)
        if not binary:
            return [Finding(
                check_id="TOOL-GITLEAKS-MISSING", title="Gitleaks availability", status="NOT_TESTED",
                severity="INFO", source=self.name, asset=str(source),
                summary="Gitleaks is not installed; its secret-detection checks were not run.",
                remediation="Install Gitleaks and rerun. See https://github.com/gitleaks/gitleaks.",
            )]
        # `dir` scans the current working tree. Git history requires a separate `gitleaks git` scan
        # and is deliberately not claimed by this initial adapter.
        with tempfile.TemporaryDirectory(prefix="securerelease-gitleaks-") as temp_dir:
            report_path = Path(temp_dir) / "gitleaks.json"
            command = [binary, "dir", str(source), "--report-format", "json", "--report-path", str(report_path),
                       "--exit-code", "0", "--no-banner"]
            try:
                proc = subprocess.run(command, capture_output=True, text=True, timeout=240, check=False)
            except subprocess.TimeoutExpired:
                return [Finding("GITLEAKS-TIMEOUT", "Gitleaks scan", "ERROR", "INFO", self.name, str(source),
                                "Gitleaks exceeded its 240-second execution limit.", remediation="Review repository size and rerun.")]
            if not report_path.exists():
                return [Finding("GITLEAKS-FAILED", "Gitleaks scan", "ERROR", "INFO", self.name, str(source),
                                "Gitleaks did not create a report file.", {"exit_code": proc.returncode, "stderr": proc.stderr[-1200:]},
                                "Check the installed Gitleaks version and command syntax.")]
            try:
                records = json.loads(report_path.read_text(encoding="utf-8") or "[]")
            except (json.JSONDecodeError, OSError) as exc:
                return [Finding("GITLEAKS-INVALID-REPORT", "Gitleaks scan", "ERROR", "INFO", self.name, str(source),
                                "Gitleaks report could not be parsed.", {"error": str(exc)[:400]},
                                "Check the Gitleaks version and report format.")]
        findings = []
        for record in records if isinstance(records, list) else []:
            # Never include Secret, Match, or raw line content in reports.
            rule_id = str(record.get("RuleID") or "SECRET-DETECTED")
            file_path = str(record.get("File") or "unknown file")
            line_number = record.get("StartLine") or record.get("LineNumber")
            findings.append(Finding(
                check_id=f"GITLEAKS-{rule_id}", title=f"Potential secret detected: {rule_id}",
                status="FAIL", severity="HIGH", source=self.name, asset=f"{file_path}:{line_number or '?'}",
                summary="Gitleaks detected a potential secret. Secret content is intentionally excluded from this report.",
                evidence={"rule_id": rule_id, "file": file_path, "line": line_number,
                          "commit": record.get("Commit"), "fingerprint": record.get("Fingerprint")},
                remediation="Confirm the finding safely, revoke/rotate the credential if valid, and remove it from the working tree and Git history as appropriate.",
            ))
        if not findings:
            findings.append(Finding(
                check_id="GITLEAKS-NO-FINDINGS", title="Gitleaks working-tree scan", status="PASS", severity="INFO",
                source=self.name, asset=str(source),
                summary="Gitleaks reported no secrets in the scanned working tree. Git history was not scanned by this adapter.",
                evidence={"mode": "directory"},
                remediation="Consider a separate Git-history scan when checking for secrets that may have been committed previously.",
            ))
        return findings
