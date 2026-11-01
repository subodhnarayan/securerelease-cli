from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse

import httpx

from securerelease.models import Finding


def tls_verify() -> bool | str:
    """Verify TLS, optionally against a custom CA bundle (for example a corporate proxy CA)."""
    for name in ("SECURERELEASE_CA_BUNDLE", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"):
        path = os.environ.get(name)
        if path and os.path.isfile(path):
            return path
    return True

USER_AGENT = "SecureRelease/0.1"
TIMEOUT = httpx.Timeout(8.0, connect=4.0)
REDIRECT_CODES = {301, 302, 303, 307, 308}


class TargetRejected(ValueError):
    """Raised when the target violates the CLI's safe-default target policy."""


def validate_target(url: str, allow_private: bool = False) -> str:
    """Validate URL shape and resolved IPs before connecting.

    This is a safe-default guard for a locally run CLI, not a complete SSRF defense
    for a multi-tenant hosted service. Hosted use also needs network egress controls
    and connection-time destination enforcement.
    """
    raw = url.strip()
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise TargetRejected("Use an absolute http:// or https:// URL.")
    if parsed.username or parsed.password or parsed.fragment:
        raise TargetRejected("URLs containing user credentials or fragments are not allowed.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise TargetRejected("The URL contains an invalid port.") from exc
    if not allow_private and port not in (None, 80, 443):
        raise TargetRejected("Only default HTTP/HTTPS ports are allowed. Use --allow-private-targets for authorized local test targets and nonstandard ports.")

    host = parsed.hostname.rstrip(".").lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        if not allow_private:
            raise TargetRejected("Local hostnames are blocked by default. Use --allow-private-targets only for an application you control.")

    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            answers = socket.getaddrinfo(host, port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise TargetRejected("Hostname could not be resolved.") from exc
        addresses = []
        for answer in answers:
            try:
                addresses.append(ipaddress.ip_address(answer[4][0]))
            except ValueError:
                continue

    if not addresses:
        raise TargetRejected("Hostname did not resolve to an IP address.")
    if not allow_private and any(not addr.is_global for addr in addresses):
        raise TargetRejected("The target resolves to a non-public IP address. Use --allow-private-targets only for an application you control.")
    return raw


def _is_loopback(host: str | None) -> bool:
    if not host:
        return False
    if host.lower() in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _finding(
    label: str,
    suffix: str,
    status: str,
    severity: str,
    summary: str,
    asset: str,
    evidence: dict | None = None,
    remediation: str = "",
) -> Finding:
    return Finding(
        check_id=f"HTTP-{suffix}",
        title=f"{label}: {suffix.replace('-', ' ').title()}",
        status=status,
        severity=severity,
        source="native_http_checks",
        asset=asset,
        summary=summary,
        evidence=evidence,
        remediation=remediation,
    )


def inspect_response(url: str, label: str, response: httpx.Response) -> list[Finding]:
    parsed = urlparse(url)
    headers = {key.lower(): value for key, value in response.headers.items()}
    findings: list[Finding] = []

    if parsed.scheme == "http" and _is_loopback(parsed.hostname):
        findings.append(_finding(
            label, "HTTPS", "WARN", "INFO",
            "Target is plain HTTP on a loopback address, which is expected for local development.",
            url, {"scheme": parsed.scheme, "loopback": True},
            "Production deployments must use HTTPS. Rerun against the deployed HTTPS URL before release.",
        ))
    else:
        findings.append(_finding(
            label, "HTTPS", "PASS" if parsed.scheme == "https" else "FAIL",
            "INFO" if parsed.scheme == "https" else "HIGH",
            "Target URL uses HTTPS." if parsed.scheme == "https" else "Target URL uses plain HTTP.",
            url, {"scheme": parsed.scheme},
            "Use HTTPS and redirect HTTP traffic to HTTPS." if parsed.scheme != "https" else
            "This observation does not assess TLS cipher strength, certificate policy, or every redirect path.",
        ))

    if parsed.scheme == "http" and response.status_code in REDIRECT_CODES:
        location = response.headers.get("location", "")
        to_https = location.lower().startswith("https://")
        findings.append(_finding(
            label, "HTTP-REDIRECT", "WARN" if to_https else "FAIL",
            "INFO" if to_https else "MEDIUM",
            "An HTTPS redirect destination was advertised." if to_https else "No HTTPS redirect destination was observed.",
            url, {"status_code": response.status_code, "location": location[:300]},
            "Redirects are not followed. Verify HTTP-to-HTTPS behavior across relevant routes.",
        ))

    header_checks = [
        ("CSP", "content-security-policy", "MEDIUM", "Define a Content-Security-Policy suited to application resources."),
        ("HSTS", "strict-transport-security", "MEDIUM", "On HTTPS, consider HSTS after confirming relevant hosts support HTTPS."),
        ("X-CONTENT-TYPE-OPTIONS", "x-content-type-options", "LOW", "Consider X-Content-Type-Options: nosniff."),
        ("REFERRER-POLICY", "referrer-policy", "LOW", "Set an appropriate Referrer-Policy."),
    ]
    for suffix, key, severity, remediation in header_checks:
        if key == "strict-transport-security" and parsed.scheme != "https":
            findings.append(_finding(label, suffix, "NOT_TESTED", "INFO",
                                     "HSTS is assessed only on HTTPS responses.", url,
                                     {"reason": "Target URL is HTTP."}, remediation))
            continue
        present = key in headers
        findings.append(_finding(
            label, suffix, "PASS" if present else "WARN", "INFO" if present else severity,
            f"{key} header is present." if present else f"{key} header was not observed.", url,
            {"value": headers.get(key, "")[:500] if present else None}, remediation,
        ))

    has_frame_protection = (
        "x-frame-options" in headers
        or "frame-ancestors" in headers.get("content-security-policy", "").lower()
    )
    findings.append(_finding(
        label, "CLICKJACKING", "PASS" if has_frame_protection else "WARN",
        "INFO" if has_frame_protection else "LOW",
        "An anti-framing control was observed." if has_frame_protection else
        "No X-Frame-Options or CSP frame-ancestors directive was observed.",
        url, {"x_frame_options": headers.get("x-frame-options")},
        "Consider X-Frame-Options or CSP frame-ancestors if framing is not required.",
    ))

    cookies = response.headers.get_list("set-cookie")
    if not cookies:
        findings.append(_finding(label, "COOKIE-ATTRIBUTES", "NOT_TESTED", "INFO",
                                 "No cookies were returned by this request; authenticated flows may behave differently.",
                                 url, {"cookie_count": 0},
                                 "Test login/session flows with authorized test credentials to assess cookie attributes."))
    for index, cookie in enumerate(cookies[:20], start=1):
        lower = cookie.lower()
        missing = [name for name, found in (
            ("Secure", "; secure" in lower),
            ("HttpOnly", "; httponly" in lower),
            ("SameSite", "samesite=" in lower),
        ) if not found]
        findings.append(_finding(
            label, f"COOKIE-{index}", "WARN" if missing else "PASS",
            "LOW" if missing else "INFO",
            "Cookie is missing one or more commonly recommended attributes." if missing else
            "Common cookie attributes were observed.",
            url, {"cookie_name": cookie.split("=", 1)[0][:100], "missing_attributes": missing},
            "Review Secure, HttpOnly, and SameSite according to the cookie's purpose and application requirements.",
        ))

    server = headers.get("server")
    powered = headers.get("x-powered-by")
    findings.append(_finding(
        label, "TECH-DISCLOSURE", "WARN" if server or powered else "PASS", "INFO",
        "Common server/framework-identifying headers were observed." if server or powered else
        "No common server/framework-identifying header was observed.",
        url, {"server": server, "x_powered_by": powered},
        "Consider minimizing unnecessary technology banners; this alone is not proof of a vulnerability.",
    ))
    findings.append(_finding(
        label, "HTTP-STATUS", "PASS" if response.status_code < 500 else "WARN",
        "INFO" if response.status_code < 500 else "MEDIUM",
        f"Received HTTP status {response.status_code}.", url,
        {"status_code": response.status_code, "content_type": response.headers.get("content-type")},
        "Review unexpected server errors and check whether the response is expected for this endpoint.",
    ))
    return findings


def _request(url: str, method: str, allow_private: bool) -> httpx.Response:
    validate_target(url, allow_private=allow_private)
    headers = {"User-Agent": USER_AGENT, "Origin": "https://securerelease.invalid"}
    if method == "OPTIONS":
        headers["Access-Control-Request-Method"] = "GET"
    else:
        headers["Range"] = "bytes=0-4095"
    # Stream and cap response-body consumption. A Range header alone cannot enforce
    # this because some servers ignore it and still return a large body.
    with httpx.Client(timeout=TIMEOUT, follow_redirects=False, verify=tls_verify(), headers=headers) as client:
        with client.stream(method, url, headers=headers) as response:
            consumed = 0
            for chunk in response.iter_bytes(chunk_size=1024):
                consumed += len(chunk)
                if consumed >= 4096:
                    break
            # Return a metadata-only response snapshot after the streamed response closes.
            return httpx.Response(
                status_code=response.status_code,
                headers=response.headers,
                request=response.request,
            )


def scan_url(url: str, label: str = "Website", allow_private: bool = False) -> list[Finding]:
    try:
        response = _request(url, "GET", allow_private=allow_private)
        findings = inspect_response(url, label, response)
    except TargetRejected as exc:
        return [Finding(
            check_id="TARGET-POLICY", title=f"{label}: Target validation", status="NOT_TESTED", severity="INFO",
            source="native_http_checks", asset=url,
            summary="Target was not scanned because it did not satisfy the safety policy.",
            evidence={"reason": str(exc)},
            remediation="Use a target you own or are authorized to assess. For local testing, explicitly opt in with --allow-private-targets.",
        )]
    except httpx.TimeoutException:
        return [Finding(
            check_id="HTTP-CONNECTIVITY", title=f"{label}: Connectivity", status="NOT_TESTED", severity="INFO",
            source="native_http_checks", asset=url, summary="HTTP request timed out.",
            evidence={"timeout_seconds": 8}, remediation="Check target availability and network reachability.",
        )]
    except httpx.HTTPError as exc:
        return [Finding(
            check_id="HTTP-CONNECTIVITY", title=f"{label}: Connectivity", status="NOT_TESTED", severity="INFO",
            source="native_http_checks", asset=url, summary="HTTP request failed.",
            evidence={"error": str(exc)[:250]}, remediation="Check DNS, TLS certificate validity, and network reachability.",
        )]

    try:
        options = _request(url, "OPTIONS", allow_private=allow_private)
        cors_headers = {k.lower(): v for k, v in options.headers.items()
                        if k.lower().startswith("access-control-")}
        origin = cors_headers.get("access-control-allow-origin", "")
        credentials = cors_headers.get("access-control-allow-credentials", "").lower() == "true"
        suspicious_advertisement = origin == "*" and credentials
        findings.append(Finding(
            "HTTP-CORS-OBSERVATION", f"{label}: CORS observation",
            "WARN" if suspicious_advertisement else "PASS",
            "LOW" if suspicious_advertisement else "INFO", "native_http_checks", url,
            "Wildcard origin and credentials were both advertised; validate the actual browser policy." if suspicious_advertisement else
            "No obvious wildcard-origin-plus-credentials combination was observed. This is not complete CORS validation.",
            {"status_code": options.status_code, "headers": cors_headers},
            "Allow only trusted origins and validate policy against intended browser clients. Browsers reject wildcard origins with credentialed requests, so this observation alone does not prove data exposure.",
        ))
    except (TargetRejected, httpx.HTTPError) as exc:
        findings.append(Finding(
            check_id="HTTP-CORS-OBSERVATION", title=f"{label}: CORS observation", status="NOT_TESTED",
            severity="INFO", source="native_http_checks", asset=url,
            summary="Could not complete the CORS observation.", evidence={"reason": str(exc)[:250]},
            remediation="Review CORS using authenticated, application-specific tests where needed.",
        ))
    return findings
