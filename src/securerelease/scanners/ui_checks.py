"""Passive analyzers over page snapshots. Used by every UI engine."""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

from securerelease.models import Finding
from securerelease.scanners.http_baseline import _is_loopback
from securerelease.scanners.ui_snapshot import CookieInfo, PageSnapshot, parse_set_cookie

SOURCE = "securerelease_ui"
MAX_LISTED = 12
CSRF_FIELD = re.compile(r"csrf|xsrf|authenticity|_token$|^token$|nonce|requestverification", re.IGNORECASE)
SESSION_COOKIE = re.compile(r"sess|auth|token|jwt|sid|login", re.IGNORECASE)
REDIRECT_PARAM = re.compile(r"^(redirect|redirect_uri|redirect_url|return|returnurl|return_to|next|url|continue|dest|destination|goto)$", re.IGNORECASE)
SENSITIVE_STORAGE_KEY = re.compile(r"token|jwt|secret|passw|api[_-]?key|session|auth", re.IGNORECASE)
COMMENT_KEYWORDS = re.compile(r"password|passwd|secret|api[_-]?key|todo|fixme|hack|credential|internal|10\.\d+\.\d+\.\d+|192\.168\.", re.IGNORECASE)
SECRET_PATTERNS = (
    ("AWS access key", "HIGH", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Private key block", "CRITICAL", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("Google API key", "MEDIUM", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack token", "HIGH", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("GitHub token", "HIGH", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("JSON Web Token", "MEDIUM", re.compile(r"\beyJ[0-9A-Za-z_-]{8,}\.eyJ[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,}\b")),
    ("Hard-coded credential assignment", "MEDIUM",
     re.compile(r"""(?i)\b(?:api[_-]?key|secret|client_secret|password|passwd|access[_-]?token)\b["']?\s*[:=]\s*["']([^"'\s]{8,})["']""")),
)


def _finding(suffix: str, title: str, status: str, severity: str, asset: str, summary: str,
             evidence: dict[str, Any] | None = None, remediation: str = "") -> Finding:
    return Finding(check_id=f"UI-{suffix}", title=f"UI: {title}", status=status, severity=severity,
                   source=SOURCE, asset=asset, summary=summary, evidence=evidence, remediation=remediation)


def mask(value: str) -> str:
    return (value[:4] + "***") if len(value) > 4 else "***"


def _listing(items: list[Any]) -> dict[str, Any]:
    return {"count": len(items), "items": items[:MAX_LISTED]}


def _same_site(url: str, base: str) -> bool:
    return urlparse(url).netloc.lower() == urlparse(base).netloc.lower()


def analyze(snapshots: list[PageSnapshot], start_url: str) -> list[Finding]:
    pages = [s for s in snapshots if s.kind == "page" and s.status < 400]
    scripts = [s for s in snapshots if s.kind == "script"]
    html_pages = [s for s in pages if s.is_html]
    findings: list[Finding] = [_https(start_url)]
    if not html_pages:
        findings.append(_finding("PAGES", "Page content", "NOT_TESTED", "INFO", start_url,
                                 "No HTML page was retrieved, so page-level checks were not run.", None,
                                 "Check that the URL serves HTML and is reachable; use --ui-engine browser for client-rendered apps."))
        return findings
    findings += _headers(html_pages, start_url)
    findings += _csp(html_pages, start_url)
    findings.append(_cookies(snapshots, start_url))
    findings.append(_mixed_content(html_pages, start_url))
    findings += _forms(html_pages, start_url)
    findings.append(_sri(html_pages, start_url))
    findings.append(_inline_scripts(html_pages, start_url))
    findings.append(_secrets(html_pages + scripts, start_url))
    findings.append(_storage(snapshots, start_url))
    findings.append(_comments(html_pages, start_url))
    findings.append(_tech(html_pages, start_url))
    findings.append(_redirect_params(html_pages, start_url))
    findings.extend(_console(snapshots, start_url))
    return findings


def _https(start_url: str) -> Finding:
    parsed = urlparse(start_url)
    if parsed.scheme == "https":
        return _finding("HTTPS", "Transport security", "PASS", "INFO", start_url, "The UI is served over HTTPS.",
                        {"scheme": "https"}, "This does not assess TLS configuration or every redirect path.")
    if _is_loopback(parsed.hostname):
        return _finding("HTTPS", "Transport security", "WARN", "INFO", start_url,
                        "The UI is plain HTTP on a loopback address, which is expected for local development.",
                        {"scheme": "http", "loopback": True}, "Production deployments must use HTTPS. Rerun against the deployed HTTPS URL.")
    return _finding("HTTPS", "Transport security", "FAIL", "HIGH", start_url, "The UI is served over plain HTTP.",
                    {"scheme": "http"}, "Serve the UI over HTTPS and redirect HTTP to HTTPS.")


def _headers(pages: list[PageSnapshot], start_url: str) -> list[Finding]:
    https = urlparse(start_url).scheme == "https"
    checks = [
        ("CSP-HEADER", "Content-Security-Policy", "content-security-policy", "MEDIUM", "Define a Content-Security-Policy suited to the UI's resources."),
        ("HSTS", "Strict-Transport-Security", "strict-transport-security", "MEDIUM", "Send HSTS on HTTPS responses once all relevant hosts support HTTPS."),
        ("NOSNIFF", "X-Content-Type-Options", "x-content-type-options", "LOW", "Send X-Content-Type-Options: nosniff."),
        ("REFERRER-POLICY", "Referrer-Policy", "referrer-policy", "LOW", "Set an appropriate Referrer-Policy."),
    ]
    out: list[Finding] = []
    for suffix, label, header, severity, advice in checks:
        if header == "strict-transport-security" and not https:
            out.append(_finding(suffix, label, "NOT_TESTED", "INFO", start_url, "HSTS is assessed only over HTTPS.",
                                {"reason": "The UI URL is HTTP."}, advice))
            continue
        missing = [p.url for p in pages if header not in p.headers]
        out.append(_finding(
            suffix, label, "WARN" if missing else "PASS", severity if missing else "INFO", start_url,
            f"{header} was missing on {len(missing)} of {len(pages)} page(s)." if missing else f"{header} was present on all {len(pages)} page(s).",
            _listing(missing), advice))
    unframed = [p.url for p in pages if "x-frame-options" not in p.headers
                and "frame-ancestors" not in p.headers.get("content-security-policy", "").lower()]
    out.append(_finding(
        "CLICKJACKING", "Clickjacking protection", "WARN" if unframed else "PASS", "MEDIUM" if unframed else "INFO", start_url,
        f"No X-Frame-Options or CSP frame-ancestors on {len(unframed)} page(s)." if unframed else "An anti-framing control was observed on all pages.",
        _listing(unframed), "Send X-Frame-Options or CSP frame-ancestors on pages that should not be embedded."))
    return out


def _csp(pages: list[PageSnapshot], start_url: str) -> list[Finding]:
    issues: list[dict[str, Any]] = []
    seen: set[str] = set()
    for page in pages:
        policy = page.headers.get("content-security-policy", "")
        if not policy or policy in seen:
            continue
        seen.add(policy)
        directives = {d.split()[0].lower(): d.split()[1:] for d in policy.split(";") if d.strip()}
        script_src = directives.get("script-src") or directives.get("default-src") or []
        problems = []
        if "'unsafe-inline'" in script_src and not any(t.startswith(("'nonce-", "'sha")) for t in script_src):
            problems.append("script-src allows 'unsafe-inline'")
        if "'unsafe-eval'" in script_src:
            problems.append("script-src allows 'unsafe-eval'")
        if "*" in script_src or "https:" in script_src or "http:" in script_src:
            problems.append("script-src allows a wildcard or whole scheme")
        if "object-src" not in directives and "default-src" not in directives:
            problems.append("object-src is not restricted")
        if problems:
            issues.append({"page": page.url, "problems": problems})
    if not seen:
        return []
    return [_finding(
        "CSP-QUALITY", "Content-Security-Policy strength", "WARN" if issues else "PASS", "MEDIUM" if issues else "INFO",
        start_url, "The observed CSP contains weak directives." if issues else "No weak script-src directive was found in the observed CSP.",
        _listing(issues), "Prefer nonce- or hash-based script-src, remove 'unsafe-inline'/'unsafe-eval', and avoid wildcards.")]


def _cookies(snapshots: list[PageSnapshot], start_url: str) -> Finding:
    https = urlparse(start_url).scheme == "https"
    cookies: dict[str, CookieInfo] = {}
    for snap in snapshots:
        for cookie in snap.cookies:
            cookies.setdefault(cookie.name, cookie)
    if not cookies:
        return _finding("COOKIES", "Cookie attributes", "NOT_TESTED", "INFO", start_url,
                        "No cookies were observed; authenticated flows may set different cookies.", {"cookie_count": 0},
                        "Run with authentication to assess session cookies.")
    problems: list[dict[str, Any]] = []
    worst = "LOW"
    for cookie in cookies.values():
        missing = []
        if https and not cookie.secure:
            missing.append("Secure")
        if not cookie.http_only:
            missing.append("HttpOnly")
        if not cookie.same_site:
            missing.append("SameSite")
        if missing:
            problems.append({"cookie": cookie.name, "missing": missing})
            if SESSION_COOKIE.search(cookie.name) and ("HttpOnly" in missing or "Secure" in missing):
                worst = "MEDIUM"
    return _finding(
        "COOKIES", "Cookie attributes", "WARN" if problems else "PASS", worst if problems else "INFO", start_url,
        f"{len(problems)} of {len(cookies)} cookie(s) are missing recommended attributes." if problems else
        f"All {len(cookies)} observed cookie(s) carry Secure/HttpOnly/SameSite as applicable.",
        _listing(problems), "Set Secure, HttpOnly (for session cookies) and an explicit SameSite on cookies. Values are never recorded.")


def _mixed_content(pages: list[PageSnapshot], start_url: str) -> Finding:
    secure_pages = [p for p in pages if urlparse(p.url).scheme == "https"]
    if not secure_pages:
        return _finding("MIXED-CONTENT", "Mixed content", "NOT_TESTED", "INFO", start_url,
                        "Mixed content applies only to HTTPS pages.", None, "Rerun against the HTTPS deployment.")
    active: list[dict[str, str]] = []
    passive: list[dict[str, str]] = []
    for page in secure_pages:
        observed = [(kind, url) for kind, url in page.parsed().resources] + [("request", u) for u in page.requests]
        for kind, url in observed:
            if url.lower().startswith("http://"):
                (active if kind in {"script", "stylesheet", "iframe", "frame", "object", "embed", "request"} else passive).append(
                    {"page": page.url, "type": kind, "resource": url[:200]})
    if active:
        return _finding("MIXED-CONTENT", "Mixed content", "FAIL", "HIGH", start_url,
                        f"{len(active)} active resource(s) are loaded over HTTP on HTTPS pages.", _listing(active),
                        "Load every sub-resource over HTTPS.")
    if passive:
        return _finding("MIXED-CONTENT", "Mixed content", "WARN", "MEDIUM", start_url,
                        f"{len(passive)} passive resource(s) are loaded over HTTP on HTTPS pages.", _listing(passive),
                        "Load images and media over HTTPS.")
    return _finding("MIXED-CONTENT", "Mixed content", "PASS", "INFO", start_url,
                    "No HTTP sub-resource was referenced from HTTPS pages.", None, "")


def _forms(pages: list[PageSnapshot], start_url: str) -> list[Finding]:
    password_http: list[dict[str, str]] = []
    password_get: list[dict[str, str]] = []
    password_cross: list[dict[str, str]] = []
    no_csrf: list[dict[str, str]] = []
    total = 0
    for page in pages:
        for form in page.parsed().forms:
            total += 1
            has_password = any(i["type"] == "password" for i in form["inputs"])
            action = form["action"]
            where = {"page": page.url, "action": action[:200], "method": form["method"]}
            if has_password:
                if urlparse(action).scheme == "http" and not _is_loopback(urlparse(action).hostname):
                    password_http.append(where)
                if form["method"] == "get":
                    password_get.append(where)
                if not _same_site(action, page.url):
                    password_cross.append(where)
            if form["method"] == "post" and not any(CSRF_FIELD.search(i["name"] or "") for i in form["inputs"]):
                no_csrf.append(where)
    out: list[Finding] = []
    if not total:
        return [_finding("FORMS", "Forms", "NOT_TESTED", "INFO", start_url, "No HTML forms were found on the crawled pages.", None,
                         "Authenticated or script-rendered forms need --ui-engine browser and credentials.")]
    for suffix, title, items, status, severity, msg, advice in (
        ("FORM-PASSWORD-HTTP", "Password form over HTTP", password_http, "FAIL", "HIGH",
         "A password form submits over plain HTTP.", "Submit credentials only over HTTPS."),
        ("FORM-PASSWORD-GET", "Password in GET request", password_get, "FAIL", "HIGH",
         "A password form uses GET, placing credentials in URLs and logs.", "Use POST for credential forms."),
        ("FORM-PASSWORD-CROSS-ORIGIN", "Password form posts cross-origin", password_cross, "WARN", "MEDIUM",
         "A password form submits to a different origin.", "Confirm the destination is a trusted identity provider."),
    ):
        if items:
            out.append(_finding(suffix, title, status, severity, start_url, msg, _listing(items), advice))
    out.append(_finding(
        "FORM-CSRF", "CSRF protection on POST forms", "WARN" if no_csrf else "PASS", "MEDIUM" if no_csrf else "INFO", start_url,
        f"{len(no_csrf)} POST form(s) have no recognizable anti-CSRF token field." if no_csrf else
        f"All POST forms among {total} form(s) include an anti-CSRF-style field.",
        _listing(no_csrf),
        "Use anti-CSRF tokens and SameSite cookies. Token-less forms may be protected by other means (for example custom headers); verify manually."))
    return out


def _sri(pages: list[PageSnapshot], start_url: str) -> Finding:
    missing: list[dict[str, str]] = []
    for page in pages:
        for script in page.parsed().scripts:
            src = script.get("src")
            if src and not script.get("integrity") and not _same_site(src, page.url):
                missing.append({"page": page.url, "resource": src[:200]})
    return _finding(
        "SRI", "Subresource Integrity for third-party assets", "WARN" if missing else "PASS", "MEDIUM" if missing else "INFO", start_url,
        f"{len(missing)} third-party script/stylesheet reference(s) lack an integrity attribute." if missing else
        "No third-party script or stylesheet without integrity was found in served HTML.",
        _listing(missing), "Add integrity and crossorigin attributes to third-party assets, or self-host them.")


def _inline_scripts(pages: list[PageSnapshot], start_url: str) -> Finding:
    inline = sum(1 for p in pages for s in p.parsed().scripts if s["inline"] and s["text"].strip())
    handlers = sum(p.parsed().inline_handlers for p in pages)
    policies = [p.headers.get("content-security-policy", "") for p in pages]
    protected = bool(policies) and all(
        pol and ("'unsafe-inline'" not in pol or "'nonce-" in pol) for pol in policies)
    if (inline or handlers) and not protected:
        return _finding("INLINE-SCRIPT", "Inline scripts without CSP protection", "WARN", "LOW", start_url,
                        f"{inline} inline script(s) and {handlers} inline event handler(s) run without a CSP that blocks injected inline code.",
                        {"inline_scripts": inline, "inline_handlers": handlers},
                        "Move scripts to external files and enforce a CSP with nonces or hashes.")
    return _finding("INLINE-SCRIPT", "Inline scripts without CSP protection", "PASS", "INFO", start_url,
                    "No unprotected inline script usage was observed.", {"inline_scripts": inline, "inline_handlers": handlers}, "")


def _secrets(items: list[PageSnapshot], start_url: str) -> Finding:
    hits: list[dict[str, str]] = []
    worst = "MEDIUM"
    order = {"MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    for item in items:
        text = item.body[:600_000]
        for label, severity, pattern in SECRET_PATTERNS:
            match = pattern.search(text)
            if match:
                value = match.group(1) if match.groups() else match.group(0)
                hits.append({"location": item.url[:200], "type": label, "preview": mask(value)})
                if order[severity] > order[worst]:
                    worst = severity
    if hits:
        return _finding("SECRETS", "Secrets in client-delivered content", "FAIL", worst, start_url,
                        f"{len(hits)} secret-like value(s) were found in HTML or JavaScript served to every visitor.",
                        _listing(hits), "Remove secrets from client code, rotate any exposed value, and keep credentials server-side. Values are masked in this report.")
    return _finding("SECRETS", "Secrets in client-delivered content", "PASS", "INFO", start_url,
                    f"No secret-like value matched in {len(items)} fetched document(s).", None,
                    "Pattern matching is limited; use Gitleaks on the source repository for deeper coverage.")


def _storage(snapshots: list[PageSnapshot], start_url: str) -> Finding:
    browser = [s for s in snapshots if s.engine == "browser"]
    if not browser:
        return _finding("STORAGE", "Browser storage", "NOT_TESTED", "INFO", start_url,
                        "Web storage can only be inspected with the browser engine.", None, "Use --ui-engine browser.")
    keys: list[dict[str, str]] = []
    for snap in browser:
        for area, names in snap.storage.items():
            keys.extend({"page": snap.url[:200], "area": area, "key": name[:80]} for name in names if SENSITIVE_STORAGE_KEY.search(name))
    if keys:
        return _finding("STORAGE", "Browser storage", "WARN", "MEDIUM", start_url,
                        f"{len(keys)} web-storage key(s) look like tokens or secrets; script access means XSS can steal them.",
                        _listing(keys), "Prefer HttpOnly cookies for session tokens. Only key names are recorded, never values.")
    return _finding("STORAGE", "Browser storage", "PASS", "INFO", start_url,
                    "No token- or secret-looking keys were found in localStorage/sessionStorage.", None, "")


def _comments(pages: list[PageSnapshot], start_url: str) -> Finding:
    hits = [{"page": p.url[:200], "comment": c[:120]} for p in pages for c in p.parsed().comments if COMMENT_KEYWORDS.search(c)]
    return _finding("HTML-COMMENTS", "Sensitive HTML comments", "WARN" if hits else "PASS", "LOW" if hits else "INFO", start_url,
                    f"{len(hits)} HTML comment(s) mention credentials, internal addresses, or TODOs." if hits else
                    "No sensitive-looking HTML comment was found.", _listing(hits),
                    "Strip comments from production HTML.")


def _tech(pages: list[PageSnapshot], start_url: str) -> Finding:
    banners: set[str] = set()
    for page in pages:
        for header in ("server", "x-powered-by", "x-aspnet-version"):
            if page.headers.get(header):
                banners.add(f"{header}: {page.headers[header][:80]}")
        if page.parsed().generator:
            banners.add(f"meta generator: {page.parsed().generator}")
    return _finding("TECH-DISCLOSURE", "Technology disclosure", "WARN" if banners else "PASS", "LOW" if banners else "INFO", start_url,
                    "Technology-identifying banners were observed." if banners else "No technology banner was observed.",
                    {"banners": sorted(banners)[:MAX_LISTED]}, "Minimize unnecessary version banners; this alone is not a vulnerability.")


def _redirect_params(pages: list[PageSnapshot], start_url: str) -> Finding:
    hits: list[dict[str, str]] = []
    for page in pages:
        for link in page.parsed().links:
            for key, value in parse_qsl(urlparse(link).query):
                if REDIRECT_PARAM.match(key) and value.lower().startswith(("http://", "https://", "//")):
                    hits.append({"page": page.url[:200], "link": link[:200], "parameter": key})
    return _finding("OPEN-REDIRECT-PARAM", "Redirect parameters", "WARN" if hits else "PASS", "LOW" if hits else "INFO", start_url,
                    f"{len(hits)} link(s) pass an absolute URL in a redirect-style parameter; confirm the target is validated." if hits else
                    "No redirect-style parameter carrying an absolute URL was found in links.",
                    _listing(hits), "Allow-list redirect destinations. Use --authorized to actively test discovered parameters.")


def _console(snapshots: list[PageSnapshot], start_url: str) -> list[Finding]:
    messages = [{"page": s.url[:200], "message": m[:160]} for s in snapshots for m in s.console_errors]
    if not any(s.engine == "browser" for s in snapshots):
        return []
    security = [m for m in messages if re.search(r"CSP|Content Security Policy|Mixed Content|CORS|blocked", m["message"], re.IGNORECASE)]
    if security:
        return [_finding("CONSOLE", "Browser console security messages", "WARN", "LOW", start_url,
                         f"{len(security)} console message(s) mention blocked content, CSP, CORS or mixed content.",
                         _listing(security), "Review the messages: they often reveal broken or misconfigured security controls.")]
    return [_finding("CONSOLE", "Browser console security messages", "PASS", "INFO", start_url,
                     "No security-related console message was captured.", {"messages": len(messages)}, "")]


def snapshot_from_reply(url: str, reply: Any, kind: str = "page") -> PageSnapshot:
    snap = PageSnapshot(url=url, status=reply.status, headers={k.lower(): v for k, v in reply.headers.items()}, body=reply.body, kind=kind)
    snap.cookies = [parse_set_cookie(c, url) for c in reply.set_cookies]
    return snap
