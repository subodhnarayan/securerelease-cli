from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from securerelease.models import Finding

SOURCE = "zap"
DEFAULT_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
DOCKER_HOST_ALIAS = "host.docker.internal"
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}
RISK_SEVERITY = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
MAX_INSTANCES = 5
# ZAP startup and add-on updates add several minutes on top of the scan budget.
STARTUP_GRACE_SECONDS = 600
# Skipping online add-on update checks cuts roughly two minutes from every run; pin the image tag for reproducibility instead.
FAST_START_OPTIONS = "-config start.checkForUpdates=false"


def zap_image() -> str:
    return os.environ.get("SECURERELEASE_ZAP_IMAGE", DEFAULT_IMAGE)


def docker_available() -> bool:
    return shutil.which("docker") is not None


def zap_status() -> str:
    """Human-readable availability string for `securerelease doctor`."""
    docker = shutil.which("docker")
    if not docker:
        return "not installed"
    try:
        proc = subprocess.run([docker, "image", "inspect", zap_image()], capture_output=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return "docker present; status unavailable"
    if proc.returncode == 0:
        return f"docker image present: {zap_image()}"
    return f"docker available; {zap_image()} will be pulled on first use"


def _container_url(url: str) -> str:
    """Rewrite loopback hosts so the ZAP container can reach services on the host machine."""
    parsed = urlparse(url)
    if (parsed.hostname or "").lower() in LOOPBACK_HOSTS:
        netloc = DOCKER_HOST_ALIAS + (f":{parsed.port}" if parsed.port else "")
        return urlunparse(parsed._replace(netloc=netloc))
    return url


def _original_url(url: str, original_base: str) -> str:
    parsed_base = urlparse(original_base)
    parsed = urlparse(url)
    if parsed.hostname == DOCKER_HOST_ALIAS and (parsed_base.hostname or "").lower() in LOOPBACK_HOSTS:
        return urlunparse(parsed._replace(netloc=parsed_base.netloc))
    return url


def _error(check_id: str, label: str, asset: str, summary: str, evidence: dict | None = None, remediation: str = "") -> Finding:
    return Finding(check_id, f"{label}: ZAP scan", "ERROR", "INFO", SOURCE, asset, summary, evidence, remediation)


class ZapScanner:
    name = SOURCE

    def available(self) -> bool:
        return docker_available()

    def scan(
        self,
        target: str,
        *,
        label: str = "Website",
        mode: str = "baseline",
        openapi_spec: str | None = None,
        authorized: bool = False,
        max_minutes: int = 5,
    ) -> list[Finding]:
        """Run ZAP against an already-validated target.

        mode="baseline": passive scan after a short spider (safe, no attack payloads).
        mode="active": active attack scan; only allowed when `authorized` is True.
        When `openapi_spec` is given, ZAP's API scan is used and endpoints come from the specification.
        """
        if mode not in {"baseline", "active"}:
            raise ValueError("ZAP mode must be baseline or active.")
        if mode == "active" and not authorized:
            return [Finding(
                "ZAP-ACTIVE-NOT-AUTHORIZED", f"{label}: ZAP active scan", "NOT_TESTED", "INFO", SOURCE, target,
                "Active scanning sends attack payloads and was not run because --authorized was not provided.",
                {"mode": mode}, "Rerun with --authorized only against systems you own or are permitted to test, preferably staging.",
            )]
        docker = shutil.which("docker")
        if not docker:
            return [Finding(
                "TOOL-ZAP-MISSING", "ZAP availability", "NOT_TESTED", "INFO", SOURCE, target,
                "Docker is not installed, so the OWASP ZAP dynamic checks were not run.",
                remediation="Install Docker and rerun. ZAP runs from the ghcr.io/zaproxy/zaproxy image.",
            )]

        with tempfile.TemporaryDirectory(prefix="securerelease-zap-") as work:
            work_dir = Path(work)
            work_dir.chmod(0o777)
            command, spec_error = self._script_args(target, mode, openapi_spec, authorized, max_minutes, work_dir)
            if spec_error:
                return [spec_error]
            container = f"securerelease-zap-{uuid.uuid4().hex[:10]}"
            full = [docker, "run", "--rm", "--name", container, "-v", f"{work_dir}:/zap/wrk:rw", zap_image(), *command]
            try:
                proc = subprocess.run(full, capture_output=True, text=True, timeout=max_minutes * 60 + STARTUP_GRACE_SECONDS, check=False)
            except subprocess.TimeoutExpired:
                subprocess.run([docker, "rm", "-f", container], capture_output=True, check=False)
                return [_error("ZAP-TIMEOUT", label, target, f"ZAP exceeded its {max_minutes + STARTUP_GRACE_SECONDS // 60}-minute execution limit and was stopped.",
                               remediation="Narrow the target or raise the time budget, then rerun.")]
            except OSError as exc:
                return [_error("ZAP-FAILED", label, target, "ZAP could not be started.", {"error": str(exc)[:300]})]
            except BaseException:
                # Ctrl-C or any other abort must not leave the container running.
                subprocess.run([docker, "rm", "-f", container], capture_output=True, check=False)
                raise
            report_file = work_dir / "zap.json"
            if not report_file.exists():
                return [_error("ZAP-FAILED", label, target, "ZAP did not produce a report. The target may be unreachable or the image failed to run.",
                               {"exit_code": proc.returncode, "stderr": proc.stderr[-1200:], "stdout": proc.stdout[-600:]},
                               "Check that Docker is running, the image can be pulled, and the target is reachable from the container.")]
            try:
                data = json.loads(report_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                return [_error("ZAP-INVALID-REPORT", label, target, "ZAP report could not be parsed.", {"error": str(exc)[:300]})]
        return self._normalize(data, proc, target, label, mode, bool(openapi_spec))

    def _script_args(self, target, mode, openapi_spec, authorized, max_minutes, work_dir):
        container_target = _container_url(target)
        if openapi_spec:
            if re.match(r"^https?://", openapi_spec):
                spec_arg = _container_url(openapi_spec)
            else:
                spec_path = Path(openapi_spec).expanduser()
                if not spec_path.is_file():
                    return [], _error("ZAP-SPEC-MISSING", "API", str(spec_path), "The OpenAPI specification file was not found.",
                                      remediation="Provide a valid path or URL with --openapi-spec.")
                shutil.copyfile(spec_path, work_dir / f"spec{spec_path.suffix or '.json'}")
                spec_arg = f"/zap/wrk/spec{spec_path.suffix or '.json'}"
            args = ["zap-api-scan.py", "-t", spec_arg, "-f", "openapi", "-J", "zap.json", "-I",
                    "-O", urlparse(container_target).netloc, "-T", str(max_minutes)]
            if not (mode == "active" and authorized):
                args.append("-S")
            return args + ["-z", FAST_START_OPTIONS], None
        script = "zap-full-scan.py" if mode == "active" else "zap-baseline.py"
        return [script, "-t", container_target, "-J", "zap.json", "-I", "-m", "2", "-T", str(max_minutes),
                "-z", FAST_START_OPTIONS], None

    def _normalize(self, data, proc, target, label, mode, api_mode) -> list[Finding]:
        findings: list[Finding] = []
        if proc.returncode not in (0, 1, 2):
            findings.append(_error(
                "ZAP-EXIT", label, target,
                "ZAP exited with an error status; parsed alerts are kept, but this run must not be treated as a clean scan.",
                {"exit_code": proc.returncode, "stderr": proc.stderr[-1000:]}, "Inspect the ZAP output and rerun."))
        urls_match = re.search(r"Total of (\d+) URLs", proc.stdout or "")
        urls_seen = int(urls_match.group(1)) if urls_match else None
        scan_kind = "api-spec" if api_mode else mode
        for site in data.get("site") or []:
            for alert in site.get("alerts") or []:
                risk = str(alert.get("riskcode", "0"))
                severity = RISK_SEVERITY.get(risk, "UNKNOWN")
                plugin = str(alert.get("pluginid") or "UNKNOWN")
                instances = alert.get("instances") or []
                first_uri = _original_url(str(instances[0].get("uri")), target) if instances else target
                findings.append(Finding(
                    check_id=f"ZAP-{plugin}", title=f"{label}: {alert.get('name') or alert.get('alert')}",
                    status="FAIL" if severity in {"CRITICAL", "HIGH"} else "WARN", severity=severity,
                    source=SOURCE, asset=first_uri,
                    summary=_clean(alert.get("desc"))[:1200] or "Alert reported by OWASP ZAP.",
                    evidence={
                        "scan_kind": scan_kind, "confidence": alert.get("confidence"), "cwe": alert.get("cweid"),
                        "instance_count": len(instances),
                        "instances": [{"uri": _original_url(str(i.get("uri")), target), "method": i.get("method"),
                                       "param": i.get("param"), "attack": i.get("attack")} for i in instances[:MAX_INSTANCES]],
                    },
                    remediation=_clean(alert.get("solution"))[:800] or "Review the alert and apply the recommended fix.",
                    references=re.findall(r"https?://\S+", _clean(alert.get("reference")))[:5],
                ))
        if not findings:
            findings.append(Finding(
                "ZAP-NO-ALERTS", f"{label}: ZAP scan", "PASS", "INFO", SOURCE, target,
                "ZAP reported no alerts for the scan performed. This does not mean the target is secure.",
                {"scan_kind": scan_kind, "urls_seen": urls_seen},
                "Confirm coverage (crawl depth, authentication, API spec) matches the application before relying on this result."))
        elif urls_seen is not None:
            findings.append(Finding(
                "ZAP-COVERAGE", f"{label}: ZAP coverage", "PASS", "INFO", SOURCE, target,
                f"ZAP observed {urls_seen} URL(s) during the {scan_kind} scan.", {"urls_seen": urls_seen, "scan_kind": scan_kind},
                "Low URL counts usually mean the crawl missed authenticated or script-driven pages."))
        return findings


def _clean(value) -> str:
    return re.sub(r"<[^>]+>", "", str(value or "")).strip()
