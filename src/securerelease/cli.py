from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from securerelease import __version__
from securerelease.config import ConfigError, prepare
from securerelease.orchestrator import available_scanners, scan
from securerelease.reports import as_html, as_json, as_markdown, as_sarif
from securerelease.wizard import run_init

SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "UNKNOWN": 0}


def _add_scan_options(scan_parser: argparse.ArgumentParser) -> None:
    scan_parser.add_argument("--env-file", metavar="FILE",
                             help="Read settings from a .env file (SECURERELEASE_* keys, see .env.example). "
                                  "Command-line flags and real environment variables take precedence")
    scan_parser.add_argument("--url", help="Website/UI URL for baseline checks and the UI scanner")
    scan_parser.add_argument("--api-url", help="API base URL for the API scanner and low-impact HTTP observations")
    scan_parser.add_argument("--source", help="Repository directory (for repository/full profiles)")
    scan_parser.add_argument("--openapi-spec", help="OpenAPI/Swagger file or URL (api, dast and full profiles; needs --api-url). "
                                                    "If omitted, the API scanner tries well-known spec locations")
    scan_parser.add_argument("--api-token-env", metavar="ENV_VAR",
                             help="Name of an environment variable holding a bearer token for test user A (the value is never printed)")
    scan_parser.add_argument("--api-token-b-env", metavar="ENV_VAR",
                             help="Environment variable holding a token for test user B; enables BOLA/IDOR checks with --authorized")
    scan_parser.add_argument("--api-auth-header-env", metavar="ENV_VAR",
                             help="Environment variable containing a custom 'Header-Name: value' sent to the API")
    scan_parser.add_argument("--ui-engine", choices=("auto", "crawler", "browser"), default=None,
                             help="auto=Playwright if installed, else the built-in crawler; browser=require Playwright (needs the [ui] extra)")
    scan_parser.add_argument("--ui-auth-header-env", metavar="ENV_VAR",
                             help="Environment variable containing 'Header-Name: value' (for example a Cookie) sent to the UI")
    scan_parser.add_argument("--ui-storage-state", metavar="FILE", help="Playwright storage-state JSON file for an authenticated UI session")
    scan_parser.add_argument("--ui-login-url", help="Login page URL for scripted form login")
    scan_parser.add_argument("--ui-user-env", metavar="ENV_VAR", help="Environment variable holding the login username")
    scan_parser.add_argument("--ui-pass-env", metavar="ENV_VAR", help="Environment variable holding the login password")
    scan_parser.add_argument("--max-pages", type=int, default=None, help="Maximum pages the UI scanner visits (default: 25)")
    scan_parser.add_argument("--max-requests", type=int, default=None,
                             help="Request budget per UI/API target, including active probes (default: 300)")
    scan_parser.add_argument("--allow-mutating", action="store_true",
                             help="Let the API scanner send POST/PUT/PATCH requests; use only on disposable test data (DELETE is never sent)")
    scan_parser.add_argument("--zap-mode", choices=("baseline", "active"), default="baseline",
                             help="baseline=passive and non-attacking (default); active=sends attack payloads (needs --authorized)")
    scan_parser.add_argument("--authorized", action="store_true",
                             help="Confirm you own or may actively test the target; enables active tests (BOLA, fuzzing, rate-limit burst, "
                                  "reflection/open-redirect probes, ZAP active mode)")
    scan_parser.add_argument("--zap-minutes", type=int, default=5, help="Time budget per ZAP scan in minutes (default: 5)")
    scan_parser.add_argument("--allow-private-targets", action="store_true",
                             help="Allow private/local IPs and nonstandard ports; only use for assets you control")
    scan_parser.add_argument("--format", dest="report_format", choices=("text", "json", "markdown", "html", "sarif"), default=None,
                             help="Report format (default: text; html for 'run')")
    scan_parser.add_argument("--output", help="Write report to this file instead of stdout")
    scan_parser.add_argument("--fail-on", default=None,
                             help="Comma-separated severity levels that should fail the command (default: critical,high)")
    scan_parser.add_argument("--no-fail-on-findings", action="store_true",
                             help="Always return success unless a scanner itself errors; useful for report-only runs")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securerelease",
        description="Run evidence-first security readiness checks locally or in CI/CD.",
        epilog="Only scan systems you own or are explicitly authorized to assess. URL checks are a limited baseline, not a penetration test.",
    )
    parser.add_argument("--version", action="version", version=f"SecureRelease {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan_parser = commands.add_parser("scan", help="Run security checks")
    scan_parser.add_argument("--profile", choices=("baseline", "repository", "full", "dast", "api", "ui"), default=None,
                             help="baseline=URL checks; repository=repo engines; full=URL + UI + API + repository; "
                                  "dast=URL checks + OWASP ZAP (requires Docker); api=OpenAPI-driven API scanner; "
                                  "ui=crawling UI scanner (default: baseline)")
    _add_scan_options(scan_parser)
    run_parser = commands.add_parser(
        "run", help="Scan using settings from .env (or flags): the profile is chosen from what is configured")
    run_parser.add_argument("--profile", choices=("baseline", "repository", "full", "dast", "api", "ui"), default=None,
                            help="Override the profile that is otherwise inferred from the configured targets")
    _add_scan_options(run_parser)
    init_parser = commands.add_parser("init", help="Answer a few questions and create a .env file")
    init_parser.add_argument("--file", default=".env", help="Where to write the settings (default: .env)")
    api_parser = commands.add_parser("api-scan", help="Run the API scanner (same as scan --profile api)")
    _add_scan_options(api_parser)
    ui_parser = commands.add_parser("ui-scan", help="Run the UI scanner (same as scan --profile ui)")
    _add_scan_options(ui_parser)

    doctor_parser = commands.add_parser("doctor", help="Show available optional scanner engines")
    doctor_parser.add_argument("--json", action="store_true", help="Print machine-readable availability data")

    return parser


def _format_text(report) -> str:
    lines = [
        f"SecureRelease {__version__} | profile={report.profile} | scan_id={report.scan_id}",
        f"Targets: {', '.join(report.targets) if report.targets else '(none)'}",
        "Summary: " + ", ".join(f"{key}={value}" for key, value in report.summary().items()),
        "",
    ]
    if not report.findings:
        lines.append("No checks were run. Inspect the selected profile and supplied inputs.")
    for finding in report.findings:
        lines.append(f"[{finding.status:10}] [{finding.severity:8}] {finding.title}")
        lines.append(f"  Asset: {finding.asset}")
        lines.append(f"  {finding.summary}")
        if finding.remediation:
            lines.append(f"  Next: {finding.remediation}")
        lines.append(f"  Check: {finding.check_id} | source: {finding.source}")
        lines.append("")
    if report.notes:
        lines.append("Notes:")
        lines.extend(f"- {note}" for note in report.notes)
    lines.extend(["", "This report describes only the checks that ran; it is not a security certification."])
    return "\n".join(lines)


def _exit_code(report, fail_on: set[str], no_fail: bool) -> int:
    if any(f.status == "ERROR" for f in report.findings):
        return 2
    if no_fail:
        return 0
    # A requested engine that is missing means the requested repository coverage
    # was not performed. Do not let a default CI gate treat that as a clean scan.
    if any(
        (f.status == "NOT_TESTED" and f.check_id.startswith("TOOL-") and f.check_id.endswith("-MISSING"))
        or (f.status == "NOT_TESTED" and f.check_id in {"TARGET-POLICY", "HTTP-CONNECTIVITY"})
        for f in report.findings
    ):
        return 2
    if any(f.status in {"FAIL", "WARN"} and f.severity in fail_on for f in report.findings):
        return 1
    return 0


def _write_report(content: str, output: str | None) -> None:
    if output:
        destination = Path(output).expanduser()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content + ("\n" if not content.endswith("\n") else ""), encoding="utf-8")
        print(f"Report written to {destination.resolve()}")
    else:
        print(content)


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)

    if args.command == "doctor":
        data = {"securerelease_version": __version__, "engines": available_scanners()}
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            print(f"SecureRelease {__version__} scanner check")
            for name, version in data["engines"].items():
                state = "AVAILABLE" if version != "not installed" else "NOT INSTALLED"
                print(f"[{state:12}] {name}: {version}")
            print("\nThe native HTTP baseline is built in. External engines are optional (ZAP runs through Docker).")
        return 0

    if args.command == "init":
        return run_init(args.file)

    if args.command in {"scan", "api-scan", "ui-scan", "run"}:
        try:
            profile, summary = prepare(args, args.command)
        except ConfigError as exc:
            parser.error(str(exc))
        if args.command == "run":
            print("SecureRelease run\n  " + "\n  ".join(summary), file=sys.stderr)
        fail_levels = {part.strip().upper() for part in args.fail_on.split(",") if part.strip()}
        invalid = fail_levels - set(SEVERITY_ORDER)
        if invalid:
            parser.error(f"Unsupported --fail-on severity: {', '.join(sorted(invalid))}")
        try:
            report = scan(
                profile=profile,
                url=args.url,
                api_url=args.api_url,
                source=args.source,
                allow_private_targets=args.allow_private_targets,
                openapi_spec=args.openapi_spec,
                zap_mode=args.zap_mode,
                authorized=args.authorized,
                zap_minutes=args.zap_minutes,
                api_token_env=args.api_token_env,
                api_token_b_env=args.api_token_b_env,
                api_auth_header_env=args.api_auth_header_env,
                ui_engine=args.ui_engine,
                ui_auth_header_env=args.ui_auth_header_env,
                ui_storage_state=args.ui_storage_state,
                ui_login_url=args.ui_login_url,
                ui_user_env=args.ui_user_env,
                ui_pass_env=args.ui_pass_env,
                max_pages=args.max_pages,
                max_requests=args.max_requests,
                allow_mutating=args.allow_mutating,
            )
        except ValueError as exc:
            parser.error(str(exc))
        if args.report_format == "json":
            output = as_json(report)
        elif args.report_format == "markdown":
            output = as_markdown(report)
        elif args.report_format == "html":
            output = as_html(report)
        elif args.report_format == "sarif":
            output = as_sarif(report)
        else:
            output = _format_text(report)
        _write_report(output, args.output)
        return _exit_code(report, fail_levels, args.no_fail_on_findings)

    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    sys.exit(main())
