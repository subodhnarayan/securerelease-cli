"""UI scanner: crawl (HTTP or browser), analyze, probe well-known paths, optional active tests."""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx

from securerelease.auth import AuthError, cookies_from_storage_state, credentials_from_env, header_from_env
from securerelease.models import Finding
from securerelease.scanners.http_baseline import TargetRejected
from securerelease.scanners.safe_http import BudgetExceeded, Reply, SafeClient, ScopeViolation
<<<<<<< HEAD
from securerelease.scanners.ui_browser import BrowserUnavailable, browser_available, crawl_with_browser
=======
from securerelease.scanners.ui_browser import BrowserLoginFailed, BrowserUnavailable, browser_available, crawl_with_browser
>>>>>>> dce590a (updated version of cli)
from securerelease.scanners.ui_checks import MAX_LISTED, REDIRECT_PARAM, SOURCE, _finding, analyze
from securerelease.scanners.ui_crawler import crawl, login_with_form
from securerelease.scanners.ui_snapshot import PageSnapshot

REFLECTION_MARKER = 'sr9x<"\'>'
REDIRECT_PROBE = "https://securerelease.invalid/"


def _not_html(reply: Reply) -> bool:
    return "html" not in reply.content_type


SENSITIVE_PATHS: tuple[tuple[str, Any, str, str], ...] = (
    ("/.git/HEAD", lambda r: r.body.startswith("ref:"), "HIGH", "Git repository metadata"),
    ("/.env", lambda r: _not_html(r) and re.search(r"^[A-Z][A-Z0-9_]{2,}=.+", r.body, re.MULTILINE) is not None,
     "CRITICAL", "Environment file"),
    ("/.DS_Store", lambda r: r.body.startswith("\x00\x00\x00\x01Bud1"), "LOW", "macOS directory metadata"),
    ("/server-status", lambda r: "Apache Server Status" in r.body, "MEDIUM", "Apache server-status page"),
    ("/phpinfo.php", lambda r: "phpinfo()" in r.body or "PHP Version" in r.body, "HIGH", "phpinfo page"),
    ("/actuator/env", lambda r: '"propertySources"' in r.body, "HIGH", "Spring Boot actuator environment"),
    ("/actuator", lambda r: '"_links"' in r.body and "actuator" in r.body, "MEDIUM", "Spring Boot actuator index"),
    ("/WEB-INF/web.xml", lambda r: "<web-app" in r.body, "HIGH", "Java web descriptor"),
    ("/backup.zip", lambda r: "zip" in r.content_type, "HIGH", "Backup archive"),
)


def probe_sensitive_paths(client: SafeClient, base_url: str) -> list[Finding]:
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    exposed: list[dict[str, str]] = []
    worst = "LOW"
    order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    checked = 0
    try:
        for path, validator, severity, label in SENSITIVE_PATHS:
            try:
                reply = client.get(root + path, max_body=32 * 1024)
            except httpx.HTTPError:
                continue
            checked += 1
            if reply.ok and validator(reply):
                exposed.append({"path": path, "type": label})
                if order[severity] > order[worst]:
                    worst = severity
        findings = [_finding(
            "EXPOSED-PATHS", "Sensitive files and debug endpoints", "FAIL" if exposed else "PASS",
            worst if exposed else "INFO", root,
            f"{len(exposed)} sensitive path(s) returned recognizable content." if exposed else
            f"{checked} well-known sensitive paths did not return recognizable content.",
            {"exposed": exposed, "paths_checked": checked},
            "Remove these files from the web root and block them at the web server. Content is validated by signature to avoid single-page-app false positives.")]
        try:
            txt = client.get(root + "/.well-known/security.txt", max_body=8 * 1024)
            has = txt.ok and "contact:" in txt.body.lower()
        except httpx.HTTPError:
            has = False
        findings.append(_finding(
            "SECURITY-TXT", "Vulnerability disclosure contact", "PASS" if has else "WARN", "INFO", root,
            "A security.txt with a contact was found." if has else "No /.well-known/security.txt contact was found.", None,
            "Publish /.well-known/security.txt so researchers know where to report issues."))
        return findings
    except BudgetExceeded:
        return [_finding("EXPOSED-PATHS", "Sensitive files and debug endpoints", "NOT_TESTED", "INFO", root,
                         "The request budget was exhausted before well-known paths were probed.", None, "Raise --max-requests.")]


def probe_source_maps(client: SafeClient, scripts: list[PageSnapshot], base_url: str) -> Finding:
    exposed: list[str] = []
    try:
        for script in scripts[:5]:
            match = re.search(r"//[#@]\s*sourceMappingURL=(\S+)", script.body[-2048:])
            candidate = urljoin(script.url, match.group(1)) if match else script.url + ".map"
            if candidate.startswith("data:"):
                continue
            try:
                reply = client.get(candidate, max_body=16 * 1024)
            except (ScopeViolation, httpx.HTTPError):
                continue
            if reply.ok and '"mappings"' in reply.body:
                exposed.append(candidate[:200])
    except BudgetExceeded:
        pass
    if not scripts:
        return _finding("SOURCE-MAPS", "Exposed source maps", "NOT_TESTED", "INFO", base_url,
                        "No same-origin script was retrieved to check for source maps.", None, "")
    return _finding(
        "SOURCE-MAPS", "Exposed source maps", "WARN" if exposed else "PASS", "LOW" if exposed else "INFO", base_url,
        f"{len(exposed)} production source map(s) are publicly readable." if exposed else "No public source map was found for inspected scripts.",
        {"maps": exposed[:MAX_LISTED]}, "Do not publish source maps in production, or restrict them to authenticated debugging.")


def active_probes(client: SafeClient, pages: list[PageSnapshot]) -> list[Finding]:
    """Reflected-input and open-redirect probes using only GET against discovered URLs."""
    candidates: list[str] = []
    for page in pages:
        parsed = page.parsed()
        candidates.extend(link for link in parsed.links if urlparse(link).query)
        for form in parsed.forms:
            names = [i["name"] for i in form["inputs"] if i["name"] and i["type"] in {"text", "search", "email", "url"}]
            if form["method"] == "get" and names and not any(i["type"] == "password" for i in form["inputs"]):
                candidates.append(form["action"].split("?")[0] + "?" + urlencode({n: "x" for n in names}))
    candidates = list(dict.fromkeys(candidates))[:15]
    reflected: list[dict[str, str]] = []
    redirects: list[dict[str, str]] = []
    tested = 0
    try:
        for url in candidates:
            parsed_url = urlparse(url)
            params = parse_qsl(parsed_url.query, keep_blank_values=True)
            for index, (key, _) in enumerate(params[:3]):
                probe_value = REDIRECT_PROBE if REDIRECT_PARAM.match(key) else REFLECTION_MARKER
                mutated = [(k, probe_value if i == index else v) for i, (k, v) in enumerate(params)]
                probe_url = urlunparse(parsed_url._replace(query=urlencode(mutated)))
                try:
                    reply = client.get(probe_url, max_body=128 * 1024)
                except (ScopeViolation, httpx.HTTPError):
                    continue
                tested += 1
                if probe_value == REDIRECT_PROBE:
                    if 300 <= reply.status < 400 and reply.headers.get("location", "").startswith(REDIRECT_PROBE):
                        redirects.append({"url": url[:200], "parameter": key})
                elif REFLECTION_MARKER in reply.body and "html" in reply.content_type:
                    reflected.append({"url": url[:200], "parameter": key})
    except BudgetExceeded:
        pass
    findings: list[Finding] = []
    if reflected:
        findings.append(_finding("REFLECTED-INPUT", "Unescaped reflected input", "WARN", "MEDIUM", client.base_url,
                                 f"{len(reflected)} parameter(s) were reflected into HTML without encoding (possible reflected XSS).",
                                 {"count": len(reflected), "items": reflected[:MAX_LISTED]},
                                 "Encode output for its HTML context and add a restrictive CSP. Confirm exploitability manually."))
    if redirects:
        findings.append(_finding("OPEN-REDIRECT", "Open redirect", "FAIL", "MEDIUM", client.base_url,
                                 f"{len(redirects)} parameter(s) redirected to an arbitrary external URL.",
                                 {"count": len(redirects), "items": redirects[:MAX_LISTED]},
                                 "Allow-list redirect destinations or use relative paths only."))
    if not findings:
        findings.append(_finding(
            "ACTIVE-PROBES", "Reflected input and open redirect probes", "PASS" if tested else "NOT_TESTED", "INFO", client.base_url,
            f"{tested} parameterized request(s) showed no unescaped reflection or open redirect." if tested else
            "No parameterized URL or GET form was discovered to probe.", {"requests": tested},
            "Only discovered GET parameters were tested; this is not a full XSS scan."))
    return findings


def scan_ui(
    url: str,
    *,
    allow_private: bool = False,
    engine: str = "auto",
    authorized: bool = False,
    max_pages: int = 25,
    max_requests: int = 300,
    auth_header_env: str | None = None,
    storage_state: str | None = None,
    login_url: str | None = None,
    user_env: str | None = None,
    pass_env: str | None = None,
    transport: httpx.BaseTransport | None = None,
    env: dict[str, str] | None = None,
) -> tuple[list[Finding], dict[str, str]]:
    if engine not in {"crawler", "browser", "auto"}:
        raise ValueError("--ui-engine must be crawler, browser, or auto.")
    headers: dict[str, str] = {}
    secrets: list[str] = []
    username = password = None
    try:
        if auth_header_env:
            headers, secrets = header_from_env(auth_header_env, env)
        if login_url or user_env or pass_env:
            if not login_url:
                raise AuthError("--ui-login-url is required when login credentials are supplied.")
            username, password = credentials_from_env(user_env, pass_env, env)
            secrets += [username, password]
        if storage_state:
            cookie_map, more = cookies_from_storage_state(storage_state, urlparse(url).hostname or "")
            if cookie_map:
                cookie_header = "; ".join(f"{k}={v}" for k, v in cookie_map.items())
                headers["Cookie"] = (headers["Cookie"] + "; " if "Cookie" in headers else "") + cookie_header
                secrets += more
    except AuthError as exc:
        return [_finding("AUTH-CONFIG", "Credentials", "ERROR", "INFO", url, str(exc), None,
                         "Export credentials in environment variables and pass only their names.")], {}

    try:
        client = SafeClient(url, allow_private=allow_private, max_requests=max_requests, headers=headers, secrets=secrets,
                            persist_cookies=True, transport=transport)
    except TargetRejected as exc:
        return [Finding(
            check_id="TARGET-POLICY", title="UI: Target validation", status="NOT_TESTED", severity="INFO", source=SOURCE, asset=url,
            summary="Target was not scanned because it did not satisfy the safety policy.", evidence={"reason": str(exc)},
            remediation="Use a target you own or are authorized to assess. For local testing, explicitly opt in with --allow-private-targets.",
        )], {}

    findings: list[Finding] = []
    versions: dict[str, str] = {}
<<<<<<< HEAD
=======
    authenticated = False
>>>>>>> dce590a (updated version of cli)
    use_browser = engine == "browser" or (engine == "auto" and browser_available())
    with client:
        snapshots: list[PageSnapshot] = []
        stats: dict[str, Any] = {}
        if use_browser:
            try:
                snapshots, stats = crawl_with_browser(
                    url, allow_private=allow_private, max_pages=max_pages, storage_state=storage_state,
                    extra_headers=headers or None,
                    login=(login_url, username, password) if login_url and username and password else None,
                )
                versions["ui-engine"] = "playwright"
<<<<<<< HEAD
=======
                authenticated = stats.get("login_verified", False)
                if login_url and username and password:
                    findings.append(_finding(
                        "AUTH-LOGIN", "Scripted login", "PASS", "INFO", login_url,
                        "The password form disappeared and the browser session survived reloading the UI target.",
                        {"login_verified": authenticated},
                        "Verification covers the browser login transition and target reload, not every authorization rule.",
                    ))
            except BrowserLoginFailed as exc:
                return [_finding(
                    "AUTH-LOGIN", "Scripted login", "ERROR", "INFO", login_url or url,
                    "The scripted login could not be verified, so authenticated pages were not scanned.",
                    {"reason": str(exc)},
                    "Verify the test credentials and login flow. Use a protected UI URL as the scan target.",
                )], {"ui-engine": "playwright"}
>>>>>>> dce590a (updated version of cli)
            except BrowserUnavailable as exc:
                findings.append(Finding(
                    check_id="TOOL-PLAYWRIGHT-MISSING", title="UI: Browser engine", status="NOT_TESTED", severity="INFO",
                    source=SOURCE, asset=url, summary="The browser engine was requested but could not run.",
                    evidence={"reason": str(exc)[:200]},
                    remediation="Install it with: pip install 'securerelease-cli[ui]' && playwright install chromium. Or use --ui-engine crawler.",
                ))
                return findings, versions
        else:
            if login_url and username and password:
<<<<<<< HEAD
                findings.append(login_with_form(client, login_url, username, password))
=======
                login_finding = login_with_form(client, login_url, username, password)
                findings.append(login_finding)
                authenticated = login_finding.status == "PASS"
>>>>>>> dce590a (updated version of cli)
            snapshots, stats = crawl(client, url, max_pages=max_pages)
            versions["ui-engine"] = "built-in crawler"

        if not [s for s in snapshots if s.kind in {"page", "redirect"}]:
            findings.append(Finding(
                check_id="HTTP-CONNECTIVITY", title="UI: Connectivity", status="NOT_TESTED", severity="INFO", source=SOURCE,
                asset=url, summary="No UI page could be retrieved, so no UI checks ran."
                + (f" First error: {stats['errors'][0]}" if stats.get("errors") else ""), evidence={"errors": stats.get("errors", [])},
                remediation="Check the URL, TLS certificate validity, and network reachability.",
            ))
            return findings, versions

        findings.extend(analyze(snapshots, url))
        findings.append(probe_source_maps(client, [s for s in snapshots if s.kind == "script"], url))
        findings.extend(probe_sensitive_paths(client, url))
        if authorized:
            findings.extend(active_probes(client, [s for s in snapshots if s.kind == "page"]))
        else:
            findings.append(_finding(
                "ACTIVE-PROBES", "Reflected input and open redirect probes", "NOT_TESTED", "INFO", url,
                "Parameter-mutating probes are active tests and require --authorized.", None,
                "Rerun with --authorized against an application you own."))
<<<<<<< HEAD
        findings.insert(0, _coverage(url, stats, bool(login_url or storage_state or headers), len(snapshots), client.requests_made))
=======
        stats["authentication_configured"] = bool(login_url or storage_state or headers)
        findings.insert(0, _coverage(url, stats, authenticated, len(snapshots), client.requests_made))
>>>>>>> dce590a (updated version of cli)
    return findings, versions


def _coverage(url: str, stats: dict[str, Any], authenticated: bool, snapshots: int, requests: int) -> Finding:
    skipped = stats.get("skipped_by_page_limit", 0)
    return _finding(
        "COVERAGE", "Crawl coverage", "WARN" if skipped else "PASS", "INFO", url,
        f"Analyzed {stats.get('pages_analyzed', 0)} page(s) using the {stats.get('engine', 'unknown')} engine"
        + (f"; {skipped} discovered URL(s) were not visited because of the page limit." if skipped else "."),
        {**stats, "authenticated": authenticated, "documents_analyzed": snapshots, "requests_sent": requests},
        "Coverage reflects only same-origin pages reachable from the start URL. Raise --max-pages for larger sites and supply credentials for authenticated areas.",
    )
