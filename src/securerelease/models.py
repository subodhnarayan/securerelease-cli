from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

STATUSES = ("PASS", "FAIL", "WARN", "NOT_TESTED", "ERROR")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")


@dataclass(slots=True)
class Finding:
    check_id: str
    title: str
    status: str
    severity: str
    source: str
    asset: str
    summary: str
    evidence: dict[str, Any] | None = None
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"Unsupported finding status: {self.status}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"Unsupported severity: {self.severity}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanReport:
    profile: str
    targets: list[str]
    findings: list[Finding] = field(default_factory=list)
    tool_versions: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    scan_id: str = ""
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: str = ""

    def summary(self) -> dict[str, int]:
        return {status: sum(1 for f in self.findings if f.status == status) for status in STATUSES}

    def to_dict(self) -> dict[str, Any]:
        return {
            "product": "SecureRelease",
            "version": __import__("securerelease").__version__,
            "scan_id": self.scan_id,
            "profile": self.profile,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "targets": self.targets,
            "summary": self.summary(),
            "tool_versions": self.tool_versions,
            "notes": self.notes,
            "findings": [f.to_dict() for f in self.findings],
            "disclaimer": (
                "This report describes only the checks that ran and the evidence observed. "
                "It is not a penetration test, a compliance certification, or proof that an application is secure."
            ),
        }
