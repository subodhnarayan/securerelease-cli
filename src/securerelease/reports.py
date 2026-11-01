from __future__ import annotations

import html
import json
import re
from importlib import resources
from typing import Any

from securerelease.models import Finding, ScanReport


def as_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=False)


def as_markdown(report: ScanReport) -> str:
    data = report.to_dict()
    lines = [
        "# SecureRelease Scan Report",
        "",
        f"- **Scan ID:** `{report.scan_id}`",
        f"- **Profile:** `{report.profile}`",
        f"- **Started:** {report.started_at}",
        f"- **Finished:** {report.finished_at or 'in progress'}",
        "- **Targets:** " + (", ".join(f"`{t}`" for t in report.targets) if report.targets else "None"),
        "",
        "## Summary",
        "",
        "| Status | Count |",
        "|---|---:|",
    ]
    for status, count in report.summary().items():
        lines.append(f"| {status} | {count} |")
    lines.extend(["", "## Findings", ""])
    for finding in report.findings:
        lines.extend([
            f"### [{finding.status}] {finding.title}",
            "",
            f"- **Check:** `{finding.check_id}`",
            f"- **Severity:** {finding.severity}",
            f"- **Source:** `{finding.source}`",
            f"- **Asset:** `{finding.asset}`",
            f"- **Summary:** {finding.summary}",
            f"- **Remediation:** {finding.remediation or 'Review the evidence and determine appropriate next steps.'}",
        ])
        if finding.references:
            lines.append("- **References:** " + ", ".join(f"<{ref}>" for ref in finding.references))
        if finding.evidence:
            # Evidence may contain scanner metadata. Scanner adapters must redact secrets before normalizing.
            evidence = json.dumps(finding.evidence, ensure_ascii=False)
            lines.extend(["", "<details>", "<summary>Evidence</summary>", "", "```json", evidence, "```", "", "</details>"])
        lines.append("")
    if report.notes:
        lines.extend(["## Notes", ""])
        lines.extend(f"- {note}" for note in report.notes)
        lines.append("")
    lines.extend(["## Limitations", "", data["disclaimer"], ""])
    return "\n".join(lines)


STATUS_ORDER = ("FAIL", "ERROR", "WARN", "NOT_TESTED", "PASS")
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
SOURCE_GROUPS = {
    "securerelease_ui": "UI scanner", "securerelease_api": "API scanner", "native_http_checks": "Website HTTP baseline",
    "zap": "OWASP ZAP (DAST)", "trivy": "Trivy (dependencies, IaC)", "gitleaks": "Gitleaks (secrets)", "semgrep": "Semgrep (SAST)",
}


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _is_gap(finding: Finding) -> bool:
    return finding.status == "ERROR" or (finding.status == "NOT_TESTED" and (
        finding.check_id in {"TARGET-POLICY", "HTTP-CONNECTIVITY"}
        or (finding.check_id.startswith("TOOL-") and finding.check_id.endswith("-MISSING"))))


def _finding_html(finding: Finding) -> str:
    rows = [
        ("Check", f"<code>{_e(finding.check_id)}</code>"),
        ("Source", _e(finding.source)),
        ("Asset", f"<code>{_e(finding.asset)}</code>"),
        ("Summary", _e(finding.summary)),
        ("Remediation", _e(finding.remediation or "Review the evidence and determine appropriate next steps.")),
    ]
    if finding.references:
        rows.append(("References", "<br>".join(_e(ref) for ref in finding.references)))
    if finding.evidence:
        rows.append(("Evidence", "<pre>" + _e(json.dumps(finding.evidence, indent=2, ensure_ascii=False)) + "</pre>"))
    body = "".join(f"<dt>{label}</dt><dd>{value}</dd>" for label, value in rows)
    haystack = " ".join([finding.title, finding.check_id, finding.asset, finding.summary, finding.source]).lower()
    return (
        f'<details class="f s-{_e(finding.status)}" data-status="{_e(finding.status)}" data-search="{_e(haystack)}">'
        f'<summary><span class="badge status s-{_e(finding.status)}">{_e(finding.status.replace("_", " "))}</span>'
        f'<span class="badge sev-{_e(finding.severity)}">{_e(finding.severity)}</span>'
        f'<span class="title">{_e(finding.title)}</span></summary>'
        f'<div class="body"><dl>{body}</dl></div></details>'
    )


def as_html(report: ScanReport) -> str:
    """Render a self-contained HTML report from templates/report.html. All values are escaped."""
    template = resources.files("securerelease").joinpath("templates/report.html").read_text(encoding="utf-8")
    data = report.to_dict()
    summary = report.summary()
    findings = sorted(report.findings, key=lambda f: (STATUS_ORDER.index(f.status), SEVERITY_RANK.get(f.severity, 5), f.title))

    blocking = [f for f in findings if f.status in {"FAIL", "WARN"} and f.severity in {"CRITICAL", "HIGH"}]
    gaps = [f for f in findings if _is_gap(f)]
    if blocking:
        verdict = ("attention", f"Action needed: {len(blocking)} high-impact finding(s)",
                   "At least one FAIL/WARN finding has CRITICAL or HIGH severity. Review these before release.")
    elif gaps:
        verdict = ("gaps", "Incomplete coverage",
                   f"{len(gaps)} check(s) could not run (errors, unreachable targets, or missing engines). Missing coverage is not a pass.")
    else:
        verdict = ("", "No blocking findings in the checks that ran",
                   "This does not mean the target is secure; only the listed checks were performed. Review warnings and NOT_TESTED items.")

    cards = "".join(
        f'<div class="card s-{status}"><div class="n">{summary[status]}</div><div class="l">{_e(status.replace("_", " "))}</div></div>'
        for status in STATUS_ORDER)
    severities = {}
    for f in findings:
        if f.status in {"FAIL", "WARN", "ERROR"}:
            severities[f.severity] = severities.get(f.severity, 0) + 1
    sev_badges = "".join(
        f'<span class="badge sev-{sev}">{sev}: {severities[sev]}</span>'
        for sev in sorted(severities, key=lambda s: SEVERITY_RANK.get(s, 5))) or '<span class="badge sev-INFO">No actionable findings</span>'
    buttons = "".join(
        f'<button type="button" data-status="{status}" aria-pressed="false">{_e(status.replace("_", " "))} ({summary[status]})</button>'
        for status in STATUS_ORDER)

    grouped: dict[str, list[Finding]] = {}
    for f in findings:
        grouped.setdefault(SOURCE_GROUPS.get(f.source, f.source), []).append(f)
    groups = "".join(
        f'<section class="grp"><h2 class="group">{_e(name)} <small>{len(items)} finding(s)</small></h2>'
        + "".join(_finding_html(f) for f in items) + "</section>"
        for name, items in grouped.items()) or '<p class="empty" style="display:block">No checks were run.</p>'

    tools = "".join(f"<tr><td>{_e(name)}</td><td>{_e(version)}</td></tr>" for name, version in report.tool_versions.items())
    values = {
        "profile": _e(report.profile), "scan_id": _e(report.scan_id), "version": _e(data["version"]),
        "targets": "<br>".join(_e(t) for t in report.targets) or "None", "started": _e(report.started_at),
        "finished": _e(report.finished_at or "in progress"), "verdict_class": verdict[0], "verdict_title": _e(verdict[1]),
        "verdict_text": _e(verdict[2]), "status_cards": cards, "severity_badges": sev_badges, "filter_buttons": buttons,
        "groups": groups, "notes": "".join(f"<li>{_e(n)}</li>" for n in report.notes) or "<li>None</li>",
        "tools": tools or "<tr><td>None recorded</td><td></td></tr>", "disclaimer": _e(data["disclaimer"]),
    }
    # Single pass so report content that happens to contain {{...}} is never re-expanded.
    return re.sub(r"\{\{(\w+)\}\}", lambda m: values.get(m.group(1), m.group(0)), template)


def as_sarif(report: ScanReport) -> str:
    """Export actionable WARN/FAIL findings to SARIF 2.1.0.

    PASS, ERROR, and NOT_TESTED records are retained in JSON/Markdown rather than
    being represented as security alerts in the SARIF export.
    """
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in report.findings:
        if finding.status not in {"FAIL", "WARN"}:
            continue
        rule_id = finding.check_id
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": finding.title[:200],
            "shortDescription": {"text": finding.title[:200]},
            "fullDescription": {"text": finding.summary[:1000]},
            "help": {"text": finding.remediation[:1500] or "Review the finding and validate applicability."},
            "properties": {"tags": ["security", "securerelease"], "source": finding.source},
        })
        level = "error" if finding.severity in {"CRITICAL", "HIGH"} else "warning" if finding.severity in {"MEDIUM", "LOW"} else "note"
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f"{finding.summary} Remediation: {finding.remediation}".strip()},
            "properties": {"status": finding.status, "severity": finding.severity,
                           "source": finding.source, "asset": finding.asset,
                           "evidence": finding.evidence or {}},
        }
        # For URL-only assets, SARIF location cannot reliably point to source code. Keep the asset in properties.
        evidence_file = (finding.evidence or {}).get("file") or (finding.evidence or {}).get("path")
        if isinstance(evidence_file, str) and evidence_file:
            uri = evidence_file
            region = {}
            evidence_line = (finding.evidence or {}).get("line")
            if isinstance(evidence_line, int) and evidence_line > 0:
                region["startLine"] = evidence_line
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": uri}, **({"region": region} if region else {})}}]
        results.append(result)
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "SecureRelease",
                "semanticVersion": __import__("securerelease").__version__,
                "rules": list(rules.values()),
            }},
            "results": results,
            "invocations": [{"executionSuccessful": not any(
                f.status == "ERROR"
                or (f.status == "NOT_TESTED" and f.check_id.startswith("TOOL-") and f.check_id.endswith("-MISSING"))
                or (f.status == "NOT_TESTED" and f.check_id in {"TARGET-POLICY", "HTTP-CONNECTIVITY"})
                for f in report.findings
            ), "properties": {"scanId": report.scan_id, "profile": report.profile}}],
        }],
    }
    return json.dumps(payload, indent=2)
