"""Specification-driven API scanner.

Passive tier (default): GET-only probes derived from an OpenAPI document, with and
without credentials. Active tier (requires `authorized=True`): BOLA/IDOR replay
between two users, bounded fuzzing, and a rate-limit burst. Mutating methods are
only used when `allow_mutating=True`, and DELETE is never sent.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from securerelease.models import Finding
from securerelease.scanners.http_baseline import TargetRejected
from securerelease.scanners.openapi import (
    DISCOVERY_PATHS, ApiSpec, Operation, SpecError, looks_like_spec, parse_spec,
)
from securerelease.scanners.safe_http import BudgetExceeded, Reply, SafeClient, ScopeViolation

SOURCE = "securerelease_api"
PROBE_ORIGIN = "https://securerelease.invalid"
MAX_LISTED = 15
STACK_TRACE_PATTERNS = {
    "python-traceback": re.compile(r"Traceback \(most recent call last\)"),
    "java-stack-trace": re.compile(r"\bat [\w$.]+\([\w$]+\.java:\d+\)"),
    "dotnet-stack-trace": re.compile(r"\bat [\w.]+\(.*\) in .+:line \d+"),
    "php-error": re.compile(r"(Fatal error|Warning|Notice): .+ in .+ on line \d+"),
    "node-stack-trace": re.compile(r"\bat .+ \(.+\.js:\d+:\d+\)"),
    "framework-debug-page": re.compile(r"(DEBUG = True|Werkzeug Debugger|Whitelabel Error Page)"),
}
SQL_ERROR_PATTERN = re.compile(
    r"(SQL syntax.*MySQL|SQLSTATE\[|ORA-\d{5}|PostgreSQL.*ERROR|SQLite3?::|sqlite3\.OperationalError|"
    r"unterminated quoted string|Microsoft OLE DB|ODBC SQL Server Driver|syntax error at or near)",
    re.IGNORECASE,
)
PASSWD_PATTERN = re.compile(r"root:[x*!]?:0:0:")
RATE_HEADERS = ("ratelimit-limit", "x-ratelimit-limit", "x-rate-limit-limit", "retry-after", "ratelimit-policy")
ID_PARAM = re.compile(r"(^id$|_id$|Id$|^uuid$)")
FUZZ_PAYLOADS = (
    ("long-input", "A" * 2048),
    ("special-characters", "'\"<>;|`${}"),
    ("sql-injection", "' OR '1'='1' -- "),
    ("path-traversal", "../../../../../../etc/passwd"),
    ("xss-marker", "<srprobe>\"'"),
    ("template-expression", "{{7*7}}"),
    ("type-confusion", "-1"),
    ("integer-overflow", "99999999999999999999"),
)


def _finding(
    suffix: str, title: str, status: str, severity: str, asset: str, summary: str,
    evidence: dict[str, Any] | None = None, remediation: str = "",
) -> Finding:
    return Finding(
        check_id=f"API-{suffix}", title=f"API: {title}", status=status, severity=severity,
        source=SOURCE, asset=asset, summary=summary, evidence=evidence, remediation=remediation,
    )


@dataclass(slots=True)
class Probe:
    op: Operation
    url: str
    anon: Reply | None = None
    authed: Reply | None = None

    @property
    def best(self) -> Reply | None:
        return self.authed or self.anon


def effective_base(api_url: str, spec: ApiSpec | None) -> str:
    base = api_url.rstrip("/")
    if spec and spec.base_path and urlparse(base).path in ("", "/"):
        return base + spec.base_path
    return base


def load_spec(client: SafeClient, spec_source: str | None) -> tuple[ApiSpec | None, list[Finding], str | None]:
    """Load an OpenAPI document from a file, a URL, or well-known locations on the target."""
    asset = spec_source or client.base_url
    try:
        if spec_source and urlparse(spec_source).scheme in ("http", "https"):
            reply = client.get(spec_source, max_body=5 * 1024 * 1024)
            if not reply.ok:
                raise SpecError(f"The specification URL returned HTTP {reply.status}.")
            return parse_spec(reply.body, spec_source), [], spec_source
        if spec_source:
            from pathlib import Path
            path = Path(spec_source).expanduser()
            if not path.is_file():
                raise SpecError("The specification file does not exist.")
            return parse_spec(path.read_text(encoding="utf-8"), path.name), [], str(path)
    except (SpecError, OSError, ScopeViolation, TargetRejected, httpx.HTTPError, BudgetExceeded) as exc:
        return None, [_finding(
            "SPEC-LOAD", "OpenAPI specification", "ERROR", "INFO", asset,
            "The OpenAPI specification could not be loaded: " + str(exc)[:200], {"reason": str(exc)[:250]},
            "Provide a reachable OpenAPI 3.x or Swagger 2.0 document (JSON, or YAML with PyYAML installed). "
            "For TLS interception errors, set SECURERELEASE_CA_BUNDLE to your corporate CA file.",
        )], None

    parsed = urlparse(client.base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    candidates: list[str] = []
    for root in dict.fromkeys([client.base_url.rstrip("/"), origin]):
        candidates.extend(root + path for path in DISCOVERY_PATHS)
    for candidate in candidates:
        try:
            reply = client.get(candidate, max_body=5 * 1024 * 1024)
            if reply.ok and looks_like_spec(reply.body):
                return parse_spec(reply.body, candidate), [], candidate
        except (SpecError, ScopeViolation, httpx.HTTPError):
            continue
        except (BudgetExceeded, TargetRejected):
            break
    return None, [], None


def spec_less_spec() -> ApiSpec:
    """A single synthetic GET operation used when no specification is available."""
    return ApiSpec(
        title="(no specification)", version="", spec_version="", servers=[], base_path="",
        operations=[Operation("GET", "", "", [], False, False, None, [])], security_schemes=[],
    )


class ApiScanner:
    def __init__(
        self,
        client: SafeClient,
        spec: ApiSpec,
        *,
        spec_origin: str | None = None,
        has_auth: bool = False,
        auth_b: dict[str, str] | None = None,
        authorized: bool = False,
        allow_mutating: bool = False,
        rate_limit_burst: int = 30,
    ) -> None:
        self.client = client
        self.spec = spec
        self.spec_origin = spec_origin
        self.has_auth = has_auth
        self.auth_b = auth_b
        self.authorized = authorized
        self.allow_mutating = allow_mutating
        self.rate_limit_burst = max(5, min(rate_limit_burst, 100))
        self.base = client.base_url.rstrip("/")
        self.errors: list[str] = []
        self.skipped: list[dict[str, str]] = []
        self.probes: list[Probe] = []

    # ---- request construction -------------------------------------------------
    def _url(self, op: Operation, overrides: dict[str, Any] | None = None) -> tuple[str, dict[str, Any]]:
        overrides = overrides or {}
        path = op.path
        for param in op.path_params():
            value = overrides.get(param.name, self.spec.sample(param.schema))
            path = path.replace("{" + param.name + "}", quote(str(value), safe=""))
        query: dict[str, Any] = {}
        for param in op.params:
            if param.location == "query" and (param.required or param.name in overrides):
                query[param.name] = overrides.get(param.name, self.spec.sample(param.schema))
        return self.base + path, query

    def _send(
        self, op: Operation, *, auth: bool, headers: dict[str, str] | None = None,
        overrides: dict[str, Any] | None = None,
    ) -> tuple[str, Reply | None]:
        url, query = self._url(op, overrides)
        body = self.spec.sample(op.body_schema) if op.body_schema is not None and op.method != "GET" else None
        extra = {"Origin": PROBE_ORIGIN, **(headers or {})}
        try:
            reply = self.client.request(
                op.method, url, headers=extra, params=query or None, json_body=body, auth=auth,
            )
            return url, reply
        except httpx.HTTPError as exc:
            self.errors.append(f"{op.key}: {exc.__class__.__name__}")
            return url, None

    # ---- orchestration --------------------------------------------------------
    def run(self) -> list[Finding]:
        asset = self.base
        probeable: list[Operation] = []
        for op in self.spec.operations:
            if op.method == "GET" or (op.method in {"POST", "PUT", "PATCH"} and self.allow_mutating):
                probeable.append(op)
            elif op.method == "DELETE":
                self.skipped.append({"operation": op.key, "reason": "DELETE requests are never sent"})
            elif op.method in {"POST", "PUT", "PATCH"}:
                self.skipped.append({"operation": op.key, "reason": "mutating method (use --allow-mutating)"})
            else:
                self.skipped.append({"operation": op.key, "reason": "method not probed"})

        for index, op in enumerate(probeable):
            try:
                url, anon = self._send(op, auth=False)
                authed = self._send(op, auth=True)[1] if self.has_auth else None
            except BudgetExceeded:
                self.skipped.extend({"operation": o.key, "reason": "request budget exhausted"} for o in probeable[index:])
                break
            except ScopeViolation as exc:
                self.skipped.append({"operation": op.key, "reason": str(exc)[:120]})
                continue
            self.probes.append(Probe(op, url, anon, authed))

        reached = [p for p in self.probes if p.best is not None]
        if not reached:
            # Shares the baseline's check id so the CI policy treats an unreachable API as exit code 2.
            return [Finding(
                check_id="HTTP-CONNECTIVITY", title="API: Connectivity", status="NOT_TESTED", severity="INFO",
                source=SOURCE, asset=asset, summary="No API request completed, so no API checks could run."
                + (f" First error: {self.errors[0]}" if self.errors else ""),
                evidence={"errors": self.errors[:5]},
                remediation="Check the API URL, TLS certificate validity, and network reachability.",
            )]
        findings: list[Finding] = [self._coverage(len(probeable))]
        findings += self._passive(reached)
        findings += self._unauthenticated(reached)
        findings += self._authenticated(reached)
        findings += self._bola(reached)
        findings += self._fuzz(reached)
        findings += self._rate_limit(reached)
        return findings

    # ---- coverage -------------------------------------------------------------
    def _coverage(self, probeable: int) -> Finding:
        total = len(self.spec.operations)
<<<<<<< HEAD
        probed = len(self.probes)
        missed = [s for s in self.skipped][:MAX_LISTED]
        no_spec = self.spec_origin is None
        evidence = {
            "spec": self.spec_origin, "title": self.spec.title, "openapi": self.spec.spec_version,
            "operations_in_spec": total, "operations_probed": probed, "operations_skipped": len(self.skipped),
=======
        probed = sum(p.best is not None for p in self.probes)
        skipped = self.skipped + [
            {"operation": p.op.key, "reason": "no HTTP response received"}
            for p in self.probes if p.best is None
        ]
        missed = skipped[:MAX_LISTED]
        excluded_delete = sum(s["reason"] == "DELETE requests are never sent" for s in skipped)
        no_spec = self.spec_origin is None
        evidence = {
            "spec": self.spec_origin, "title": self.spec.title, "openapi": self.spec.spec_version,
            "operations_in_spec": total, "operations_probed": probed, "operations_skipped": len(skipped),
            "operations_eligible": probeable, "delete_operations_excluded": excluded_delete,
>>>>>>> dce590a (updated version of cli)
            "skipped": missed, "secured_operations": sum(1 for o in self.spec.operations if o.secured),
            "security_schemes": self.spec.security_schemes, "request_budget_used": self.client.requests_made,
        }
        if no_spec:
            return _finding(
                "COVERAGE", "Endpoint coverage", "WARN", "INFO", self.base,
                "No OpenAPI specification was supplied or discovered; only the base URL was probed.",
                evidence, "Pass --openapi-spec so every documented endpoint can be exercised and coverage measured.",
            )
        full = probed == total
<<<<<<< HEAD
        return _finding(
            "COVERAGE", "Endpoint coverage", "PASS" if full else "WARN", "INFO", self.base,
            f"Probed {probed} of {total} documented operations." + ("" if full else " Skipped operations are listed in evidence."),
            evidence,
            "Coverage describes requests sent, not security assurance. Enable --allow-mutating on a disposable test environment to cover write operations.",
=======
        explanation = (
            f" {excluded_delete} DELETE operation(s) intentionally excluded: the scanner never deletes data."
            if excluded_delete else ""
        )
        advice = "Coverage describes responses received, not successful business flows or security assurance."
        if excluded_delete:
            advice += " Test DELETE behavior separately with disposable fixtures; no CLI flag enables DELETE."
        if any(s["reason"] == "mutating method (use --allow-mutating)" for s in skipped):
            advice += " Enable --allow-mutating on a disposable test environment to cover POST/PUT/PATCH."
        if any(s["reason"] == "request budget exhausted" for s in skipped):
            advice += " Raise --max-requests to cover operations skipped by the request budget."
        if any(s["reason"] == "no HTTP response received" for s in skipped):
            advice += " Resolve connectivity errors before relying on coverage."
        return _finding(
            "COVERAGE", "Endpoint coverage", "PASS" if full else "WARN", "INFO", self.base,
            f"Probed {probed} of {total} documented operations." + explanation
            + ("" if full else " Skipped operations are listed in evidence."),
            evidence,
            advice,
>>>>>>> dce590a (updated version of cli)
        )

    # ---- passive checks -------------------------------------------------------
    def _passive(self, probes: list[Probe]) -> list[Finding]:
        findings: list[Finding] = []
        https = urlparse(self.base).scheme == "https"
        missing: dict[str, list[str]] = {"x-content-type-options": [], "strict-transport-security": [], "cache-control": []}
        cors_creds, cors_reflect, cors_wild = [], [], []
        leaks: list[dict[str, str]] = []
        disclosure: set[str] = set()
        errors_5xx: list[dict[str, Any]] = []
        undocumented: list[dict[str, Any]] = []

        for probe in probes:
            reply, key = probe.best, probe.op.key
            assert reply is not None
            headers = reply.headers
            if "x-content-type-options" not in headers:
                missing["x-content-type-options"].append(key)
            if https and "strict-transport-security" not in headers:
                missing["strict-transport-security"].append(key)
            if probe.authed is not None and probe.authed.ok:
                cache = headers.get("cache-control", "").lower()
                if not any(token in cache for token in ("no-store", "private", "no-cache")):
                    missing["cache-control"].append(key)

            acao, acac = headers.get("access-control-allow-origin", ""), headers.get("access-control-allow-credentials", "").lower() == "true"
            if acao == PROBE_ORIGIN:
                (cors_creds if acac else cors_reflect).append(key)
            elif acao == "*" and probe.op.secured:
                cors_wild.append(key)

            for name, pattern in STACK_TRACE_PATTERNS.items():
                match = pattern.search(reply.body)
                if match:
                    start = max(0, match.start() - 40)
                    leaks.append({"endpoint": key, "pattern": name, "excerpt": reply.body[start:start + 160]})
                    break
            for header in ("server", "x-powered-by", "x-aspnet-version"):
                value = headers.get(header, "")
                if value and (header != "server" or re.search(r"\d", value)):
                    disclosure.add(f"{header}: {value[:80]}")
            if reply.status >= 500:
                errors_5xx.append({"endpoint": key, "status": reply.status})
            documented = probe.op.responses
            if documented and "default" not in documented and reply.status < 400:
                if str(reply.status) not in documented and f"{reply.status // 100}XX" not in documented:
                    undocumented.append({"endpoint": key, "status": reply.status, "documented": documented[:8]})

        def listing(items: list[Any]) -> dict[str, Any]:
            return {"count": len(items), "endpoints": items[:MAX_LISTED]}

        header_advice = {
            "x-content-type-options": ("NOSNIFF", "LOW", "Send X-Content-Type-Options: nosniff on API responses."),
            "strict-transport-security": ("HSTS", "MEDIUM", "Send Strict-Transport-Security on HTTPS API responses."),
            "cache-control": ("CACHE-CONTROL", "LOW", "Send Cache-Control: no-store (or private) on authenticated responses."),
        }
        header_titles = {
            "x-content-type-options": "X-Content-Type-Options", "strict-transport-security": "Strict-Transport-Security",
            "cache-control": "Cache-Control on authenticated responses",
        }
        for header, endpoints in missing.items():
            suffix, severity, advice = header_advice[header]
            if header == "strict-transport-security" and not https:
                findings.append(_finding(suffix, "HSTS", "NOT_TESTED", "INFO", self.base,
                                         "HSTS is assessed only over HTTPS.", {"reason": "API URL is HTTP."}, advice))
            elif header == "cache-control" and not self.has_auth:
                findings.append(_finding(suffix, "Caching of authenticated responses", "NOT_TESTED", "INFO", self.base,
                                         "No credentials were supplied, so authenticated responses were not observed.", None, advice))
            else:
                findings.append(_finding(
                    suffix, header_titles[header],
                    "WARN" if endpoints else "PASS", severity if endpoints else "INFO", self.base,
                    f"{header} was missing on {len(endpoints)} probed endpoint(s)." if endpoints else f"{header} was present on every probed endpoint.",
                    listing(endpoints), advice,
                ))

        if cors_creds:
            findings.append(_finding("CORS", "CORS policy", "FAIL", "HIGH", self.base,
                "An untrusted Origin was reflected together with Access-Control-Allow-Credentials: true.",
                listing(cors_creds), "Allow only an explicit list of trusted origins; never reflect arbitrary origins with credentials."))
        elif cors_reflect:
            findings.append(_finding("CORS", "CORS policy", "WARN", "MEDIUM", self.base,
                "An untrusted Origin was reflected in Access-Control-Allow-Origin.",
                listing(cors_reflect), "Allow only trusted origins, especially for authenticated endpoints."))
        elif cors_wild:
            findings.append(_finding("CORS", "CORS policy", "WARN", "LOW", self.base,
                "Endpoints the specification marks as secured return a wildcard Access-Control-Allow-Origin.",
                listing(cors_wild), "Restrict origins on authenticated endpoints."))
        else:
            findings.append(_finding("CORS", "CORS policy", "PASS", "INFO", self.base,
                "No reflected or wildcard CORS policy on secured endpoints was observed for the probed requests.",
                None, "This is not a complete CORS review."))

        findings.append(_finding(
            "ERROR-DISCLOSURE", "Verbose error disclosure", "FAIL" if leaks else "PASS",
            "MEDIUM" if leaks else "INFO", self.base,
            f"Stack traces or debug output were returned by {len(leaks)} endpoint(s)." if leaks else
            "No stack-trace or debug output was observed in probed responses.",
            listing(leaks), "Return generic error bodies and log details server-side. Disable debug mode in production.",
        ))
        findings.append(_finding(
            "TECH-DISCLOSURE", "Technology disclosure", "WARN" if disclosure else "PASS", "LOW" if disclosure else "INFO",
            self.base, "Version-bearing technology headers were observed." if disclosure else "No version-bearing technology header was observed.",
            {"headers": sorted(disclosure)[:MAX_LISTED]}, "Remove or genericize Server/X-Powered-By version banners.",
        ))
        if errors_5xx:
            findings.append(_finding(
                "SERVER-ERROR", "Server errors on valid requests", "WARN", "MEDIUM", self.base,
                f"{len(errors_5xx)} endpoint(s) returned HTTP 5xx for a specification-valid request.", listing(errors_5xx),
                "Investigate unhandled errors; they often indicate missing validation or availability risk.",
            ))
        if undocumented:
            findings.append(_finding(
                "UNDOCUMENTED-STATUS", "Responses missing from the specification", "WARN", "LOW", self.base,
                f"{len(undocumented)} endpoint(s) returned a success status not declared in the specification.", listing(undocumented),
                "Keep the specification and implementation in sync so clients and tests rely on accurate contracts.",
            ))
        findings.append(self._methods(probes))
        return findings

    def _methods(self, probes: list[Probe]) -> Finding:
        documented: dict[str, set[str]] = {}
        for op in self.spec.operations:
            documented.setdefault(op.path, set()).add(op.method)
        unexpected: list[dict[str, Any]] = []
        trace: list[str] = []
        observed = 0
        seen: set[str] = set()
        for probe in probes:
            if probe.op.path in seen or len(seen) >= 10:
                continue
            seen.add(probe.op.path)
            try:
                reply = self.client.request("OPTIONS", probe.url, headers={"Origin": PROBE_ORIGIN}, auth=False)
            except (BudgetExceeded, ScopeViolation, httpx.HTTPError):
                continue
            allow = reply.headers.get("allow", "")
            if not allow:
                continue
            observed += 1
            methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
            extra = sorted(methods - documented.get(probe.op.path, set()) - {"HEAD", "OPTIONS"})
            if "TRACE" in methods:
                trace.append(probe.op.path)
            if extra and probe.op.path:
                unexpected.append({"path": probe.op.path, "undocumented_methods": extra})
        if not observed:
            return _finding("METHODS", "HTTP methods", "NOT_TESTED", "INFO", self.base,
                            "No Allow header was returned, so permitted methods could not be enumerated.", None,
                            "Return an Allow header on OPTIONS and 405 responses, and restrict unused methods.")
        if trace:
            return _finding("METHODS", "HTTP methods", "WARN", "MEDIUM", self.base, "HTTP TRACE is enabled.",
                            {"paths": trace[:MAX_LISTED]}, "Disable TRACE.")
        if unexpected:
            return _finding("METHODS", "HTTP methods", "WARN", "LOW", self.base,
                            f"{len(unexpected)} path(s) advertise methods not documented in the specification.",
                            {"count": len(unexpected), "paths": unexpected[:MAX_LISTED]},
                            "Disable unused methods or document them.")
        return _finding("METHODS", "HTTP methods", "PASS", "INFO", self.base,
                        f"Advertised methods matched the specification for {observed} path(s).", None,
                        "Only advertised methods were compared; undeclared methods were not attempted.")

    # ---- access control -------------------------------------------------------
    def _unauthenticated(self, probes: list[Probe]) -> list[Finding]:
        secured = [p for p in probes if p.op.secured and p.anon is not None]
        if not secured:
            reason = ("The specification declares no security requirement on any probed operation."
                      if not any(p.op.secured for p in probes) else "Secured operations did not return a response.")
            return [_finding("UNAUTH-ACCESS", "Unauthenticated access to secured operations", "NOT_TESTED", "INFO",
                             self.base, reason, None,
                             "Declare security requirements in the specification so access control can be verified.")]
        exposed = [{"endpoint": p.op.key, "status": p.anon.status} for p in secured if p.anon.ok]
        enforced = [p.op.key for p in secured if p.anon.status in (401, 403)]
        inconclusive = [{"endpoint": p.op.key, "status": p.anon.status} for p in secured
                        if not p.anon.ok and p.anon.status not in (401, 403)]
        evidence = {"enforced": len(enforced), "exposed": exposed[:MAX_LISTED], "inconclusive": inconclusive[:MAX_LISTED]}
        if exposed:
            return [_finding(
                "UNAUTH-ACCESS", "Unauthenticated access to secured operations", "FAIL", "HIGH", self.base,
                f"{len(exposed)} operation(s) marked as secured returned success without credentials.", evidence,
                "Enforce authentication on every operation that the specification declares as secured.",
            )]
        if enforced:
            return [_finding(
                "UNAUTH-ACCESS", "Unauthenticated access to secured operations", "PASS", "INFO", self.base,
                f"{len(enforced)} secured operation(s) rejected unauthenticated requests"
                + (f"; {len(inconclusive)} were inconclusive (non-auth errors such as 404/400)." if inconclusive else "."),
                evidence, "Inconclusive operations need valid sample data (for example real object IDs) to be assessed.",
            )]
        return [_finding(
            "UNAUTH-ACCESS", "Unauthenticated access to secured operations", "NOT_TESTED", "INFO", self.base,
            "No secured operation produced a conclusive 401/403 or success response with generated sample data.",
            evidence, "Provide valid sample data or fixtures so requests reach the authorization layer.",
        )]

    def _authenticated(self, probes: list[Probe]) -> list[Finding]:
        if not self.has_auth:
            return [_finding("AUTH-SCAN", "Authenticated scan", "NOT_TESTED", "INFO", self.base,
                             "No credentials were supplied, so only unauthenticated behavior was observed.", None,
                             "Supply a test-user token with --api-token-env (and a second user with --api-token-b-env for BOLA checks).")]
        authed = [p for p in probes if p.authed is not None]
        rejected = [p.op.key for p in authed if p.authed.status in (401, 403) and p.op.secured]
        accepted = [p.op.key for p in authed if p.authed.ok and p.op.secured]
        if authed and len(rejected) == len([p for p in authed if p.op.secured]) and rejected:
            return [_finding("AUTH-SCAN", "Authenticated scan", "NOT_TESTED", "INFO", self.base,
                             "The supplied credentials were rejected on every secured operation.",
                             {"rejected": rejected[:MAX_LISTED]}, "Check that the token is valid and unexpired for this environment.")]
        return [_finding("AUTH-SCAN", "Authenticated scan", "PASS", "INFO", self.base,
                         f"Authenticated requests were sent to {len(authed)} operation(s); {len(accepted)} secured operation(s) accepted the credentials.",
                         {"accepted": accepted[:MAX_LISTED]}, "Authenticated coverage is limited to the operations and sample data probed.")]

    def _bola(self, probes: list[Probe]) -> list[Finding]:
        title = "Object-level authorization (BOLA/IDOR)"
        if not (self.has_auth and self.auth_b):
            return [_finding("BOLA", title, "NOT_TESTED", "INFO", self.base,
                             "BOLA testing needs credentials for two different users.", None,
                             "Supply --api-token-env and --api-token-b-env for two test users, plus --authorized.")]
        if not self.authorized:
            return [_finding("BOLA", title, "NOT_TESTED", "INFO", self.base,
                             "BOLA replay is an active test and requires --authorized.", None,
                             "Rerun with --authorized against an environment you own.")]
        candidates = [
            p.op for p in probes
            if p.op.method == "GET" and len(p.op.path_params()) == 1 and ID_PARAM.search(p.op.path_params()[0].name)
            and p.op.path.rstrip("/").endswith("}")
        ][:8]
        if not candidates:
            return [_finding("BOLA", title, "NOT_TESTED", "INFO", self.base,
                             "No single-ID GET operation (such as /users/{id}) was found in the specification.", None,
                             "Document object-by-ID endpoints in the specification.")]
        identical: list[dict[str, Any]] = []
        differing: list[dict[str, Any]] = []
        denied = public = 0
        try:
            for op in candidates:
                param = op.path_params()[0]
                collection = op.path[: op.path.rindex("/")]
                ids_a = self._harvest(collection, None)
                ids_b = self._harvest(collection, self.auth_b)
                sample = str(self.spec.sample(param.schema))
                for owner_ids, owner_headers, other_headers, other_name in (
                    (ids_a or [sample], None, self.auth_b, "B"), (ids_b, self.auth_b, None, "A"),
                ):
                    for object_id in owner_ids[:3]:
                        _, owner = self._send(op, auth=owner_headers is None, headers=owner_headers, overrides={param.name: object_id})
                        if owner is None or not owner.ok:
                            continue
                        _, anon = self._send(op, auth=False, overrides={param.name: object_id})
                        if anon is not None and anon.ok:
                            public += 1
                            continue
                        _, other = self._send(op, auth=other_headers is None, headers=other_headers, overrides={param.name: object_id})
                        if other is None or not other.ok:
                            denied += 1
                            continue
                        entry = {"endpoint": op.key, "object_id": object_id, "other_user": other_name,
                                 "same_body": _digest(owner.body) == _digest(other.body)}
                        (identical if entry["same_body"] else differing).append(entry)
        except BudgetExceeded:
            pass
        evidence = {"vulnerable": identical[:MAX_LISTED], "needs_review": differing[:MAX_LISTED],
                    "denied": denied, "public_skipped": public}
        if identical:
            return [_finding("BOLA", title, "FAIL", "HIGH", self.base,
                             f"A user could read another user's object by ID on {len({e['endpoint'] for e in identical})} endpoint(s).",
                             evidence, "Enforce object-level ownership checks on every ID-based endpoint, not just authentication.")]
        if differing:
            return [_finding("BOLA", title, "WARN", "MEDIUM", self.base,
                             "One user received a successful response for another user's object ID; bodies differ and need review.",
                             evidence, "Verify the response does not expose data belonging to the other user.")]
        if denied:
            return [_finding("BOLA", title, "PASS", "INFO", self.base,
                             f"Cross-user reads were denied for {denied} object lookup(s).", evidence,
                             "Only readable IDs discovered through list endpoints or sample data were tested.")]
        return [_finding("BOLA", title, "NOT_TESTED", "INFO", self.base,
                         "No non-public object ID readable by one user could be found.", evidence,
                         "Provide list endpoints or documented example IDs that belong to each test user.")]

    def _harvest(self, collection: str, headers: dict[str, str] | None) -> list[str]:
        try:
            reply = self.client.request("GET", self.base + collection, auth=headers is None, headers=headers)
        except (ScopeViolation, httpx.HTTPError):
            return []
        data = reply.json() if reply.ok else None
        items: Any = data
        if isinstance(data, dict):
            items = next((v for v in data.values() if isinstance(v, list)), [])
        ids: list[str] = []
        for item in items if isinstance(items, list) else []:
            if isinstance(item, dict):
                value = next((item[k] for k in ("id", "uuid", "_id", "ID") if k in item), None)
                if isinstance(value, (str, int)) and not isinstance(value, bool):
                    ids.append(str(value))
        return ids[:3]

    # ---- active tier ----------------------------------------------------------
    def _fuzz(self, probes: list[Probe]) -> list[Finding]:
        title = "Input handling (bounded fuzzing)"
        if not self.authorized:
            return [_finding("FUZZ", title, "NOT_TESTED", "INFO", self.base,
                             "Fuzzing sends malformed and attack-like input and requires --authorized.", None,
                             "Rerun with --authorized against a test environment you own.")]
        targets = [p for p in probes if p.best is not None and any(
            prm.location in ("path", "query") for prm in p.op.params)][:10]
        if not targets:
            return [_finding("FUZZ", title, "NOT_TESTED", "INFO", self.base,
                             "No probed operation has path or query parameters to fuzz.", None, "")]
        server_errors: list[dict[str, Any]] = []
        injection: list[dict[str, Any]] = []
        traversal: list[dict[str, Any]] = []
        reflection: list[dict[str, Any]] = []
        template: list[dict[str, Any]] = []
        disclosure: list[dict[str, Any]] = []
        sent = 0
        try:
            for probe in targets:
                base_reply = probe.best
                assert base_reply is not None
                for param in [p for p in probe.op.params if p.location in ("path", "query")][:3]:
                    for name, payload in FUZZ_PAYLOADS:
                        _, reply = self._send(probe.op, auth=self.has_auth, overrides={param.name: payload})
                        sent += 1
                        if reply is None:
                            continue
                        where = {"endpoint": probe.op.key, "parameter": param.name, "payload": name, "status": reply.status}
                        if PASSWD_PATTERN.search(reply.body):
                            traversal.append(where)
                        elif SQL_ERROR_PATTERN.search(reply.body) and not SQL_ERROR_PATTERN.search(base_reply.body):
                            injection.append(where)
                        elif reply.status >= 500 and base_reply.status < 500:
                            server_errors.append(where)
                        if any(p.search(reply.body) for p in STACK_TRACE_PATTERNS.values()) and not any(
                                p.search(base_reply.body) for p in STACK_TRACE_PATTERNS.values()):
                            disclosure.append(where)
                        if name == "xss-marker" and "<srprobe>" in reply.body and "html" in reply.content_type:
                            reflection.append(where)
                        if name == "template-expression" and "{{7*7}}" not in reply.body and "49" in reply.body and "49" not in base_reply.body:
                            template.append(where)
        except BudgetExceeded:
            pass
        out: list[Finding] = []

        def add(suffix: str, status: str, severity: str, summary: str, items: list[dict[str, Any]], advice: str) -> None:
            if items:
                out.append(_finding(suffix, title, status, severity, self.base, summary,
                                    {"count": len(items), "examples": items[:MAX_LISTED]}, advice))

        add("FUZZ-TRAVERSAL", "FAIL", "CRITICAL", "A path-traversal payload returned /etc/passwd content.", traversal,
            "Never build file paths from user input; canonicalize and restrict to an allow-listed directory.")
        add("FUZZ-INJECTION", "FAIL", "HIGH", "An injection payload triggered a database error message.", injection,
            "Use parameterized queries and return generic errors.")
        add("FUZZ-ERROR-DISCLOSURE", "FAIL", "MEDIUM", "Malformed input made the API return a stack trace or debug output.", disclosure,
            "Return generic error bodies and log details server-side. Disable debug mode in production.")
        add("FUZZ-SERVER-ERROR", "WARN", "MEDIUM", "Malformed input caused HTTP 5xx responses.", server_errors,
            "Validate types, ranges and lengths and return 4xx for invalid input.")
        add("FUZZ-REFLECTION", "WARN", "MEDIUM", "Input was reflected unescaped in an HTML response.", reflection,
            "Encode output for its context and avoid returning user input in HTML.")
        add("FUZZ-TEMPLATE", "WARN", "MEDIUM", "A template expression appears to have been evaluated (low confidence; verify manually).",
            template, "Never pass user input to template engines as template source.")
        if not out:
            out.append(_finding("FUZZ", title, "PASS" if sent else "NOT_TESTED", "INFO", self.base,
                                f"{sent} fuzz request(s) across {len(targets)} operation(s) produced no anomaly detected by these heuristics.",
                                {"requests": sent, "payload_classes": [n for n, _ in FUZZ_PAYLOADS]},
                                "A clean result covers only these payload classes; it is not a substitute for a dedicated DAST scan."))
        return out

    def _rate_limit(self, probes: list[Probe]) -> list[Finding]:
        title = "Rate limiting"
        if not self.authorized:
            return [_finding("RATE-LIMIT", title, "NOT_TESTED", "INFO", self.base,
                             "The rate-limit probe sends a request burst and requires --authorized.", None,
                             "Rerun with --authorized against a test environment you own.")]
        target = next((p for p in probes if p.op.method == "GET" and p.best is not None and p.best.ok), None)
        if target is None:
            return [_finding("RATE-LIMIT", title, "NOT_TESTED", "INFO", self.base,
                             "No GET operation returned success, so a burst could not be sent.", None, "")]
        statuses: list[int] = []
        rate_headers: set[str] = set()
        try:
            for _ in range(self.rate_limit_burst):
                _, reply = self._send(target.op, auth=self.has_auth)
                if reply is None:
                    break
                statuses.append(reply.status)
                rate_headers.update(h for h in RATE_HEADERS if h in reply.headers)
                if reply.status == 429:
                    break
        except BudgetExceeded:
            pass
        evidence = {"endpoint": target.op.key, "requests_sent": len(statuses), "rate_limit_headers": sorted(rate_headers),
                    "status_counts": {str(s): statuses.count(s) for s in sorted(set(statuses))}}
        if len(statuses) < 5:
            return [_finding("RATE-LIMIT", title, "NOT_TESTED", "INFO", self.base,
                             "The burst was cut short, so rate limiting could not be assessed.", evidence, "")]
        if 429 in statuses or rate_headers:
            return [_finding("RATE-LIMIT", title, "PASS", "INFO", self.base,
                             "Throttling signals (HTTP 429 or rate-limit headers) were observed.", evidence,
                             "A small burst only detects obvious throttling; tune limits for login and expensive endpoints separately.")]
        return [_finding("RATE-LIMIT", title, "WARN", "MEDIUM", self.base,
                         f"{len(statuses)} rapid requests were all served with no throttling signal.", evidence,
                         "Add rate limiting (per user and per IP), especially on authentication and costly endpoints.")]


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def scan_api(
    api_url: str,
    *,
    allow_private: bool = False,
    spec_source: str | None = None,
    token_env: str | None = None,
    token_b_env: str | None = None,
    auth_header_env: str | None = None,
    authorized: bool = False,
    allow_mutating: bool = False,
    max_requests: int = 300,
    transport: httpx.BaseTransport | None = None,
    env: dict[str, str] | None = None,
) -> tuple[list[Finding], dict[str, str]]:
    """Run the API scanner end to end and return findings plus tool-version notes."""
    from securerelease.auth import AuthError, bearer_header_from_env, header_from_env

    try:
        headers: dict[str, str] = {}
        secrets: list[str] = []
        if token_env:
            headers, secrets = bearer_header_from_env(token_env, env)
        if auth_header_env:
            extra, more = header_from_env(auth_header_env, env)
            headers.update(extra)
            secrets += more
        auth_b = None
        if token_b_env:
            auth_b, more = bearer_header_from_env(token_b_env, env)
            secrets += more
    except AuthError as exc:
        return [_finding("AUTH-CONFIG", "Credentials", "ERROR", "INFO", api_url, str(exc),
                         None, "Export the token in an environment variable and pass only its name.")], {}

    try:
        client = SafeClient(api_url, allow_private=allow_private, max_requests=max_requests, headers=headers,
                            secrets=secrets, allow_mutating=allow_mutating, transport=transport)
    except TargetRejected as exc:
        return [Finding(
            check_id="TARGET-POLICY", title="API: Target validation", status="NOT_TESTED", severity="INFO",
            source=SOURCE, asset=api_url, summary="Target was not scanned because it did not satisfy the safety policy.",
            evidence={"reason": str(exc)},
            remediation="Use a target you own or are authorized to assess. For local testing, explicitly opt in with --allow-private-targets.",
        )], {}
    with client:
        try:
            spec, problems, origin = load_spec(client, spec_source)
        except httpx.HTTPError:
            spec, problems, origin = None, [], None
        if problems:
            return problems, {}
        if spec is not None:
            # Re-base on the specification's server path when the user supplied only a host.
            client.base_url = effective_base(client.base_url, spec)
        scanner = ApiScanner(
            client, spec or spec_less_spec(), spec_origin=origin if spec else None,
            has_auth=bool(headers), auth_b=auth_b, authorized=authorized, allow_mutating=allow_mutating,
        )
        findings = scanner.run()
    return findings, {"api-scanner": "built-in"}
