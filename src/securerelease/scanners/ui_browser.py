"""Optional Playwright engine for client-rendered applications.

Requires `pip install 'securerelease-cli[ui]'` and `playwright install chromium`.
Every navigation and sub-request passes the same target policy as the HTTP client,
and the crawl never leaves the starting origin.
"""
from __future__ import annotations

import importlib.util
from collections import deque
from typing import Any
from urllib.parse import urldefrag, urlparse

from securerelease.scanners.http_baseline import TargetRejected, validate_target
from securerelease.scanners.safe_http import origin_of
from securerelease.scanners.ui_crawler import SKIP_PATH, STATIC_EXTENSIONS
from securerelease.scanners.ui_snapshot import CookieInfo, PageSnapshot, parse_html, parse_set_cookie

MAX_SCRIPT_CHARS = 600_000
NAV_TIMEOUT_MS = 20_000


class BrowserUnavailable(RuntimeError):
    """Playwright or its browser binary is not installed."""


def browser_available() -> bool:
    return importlib.util.find_spec("playwright") is not None


def browser_status() -> str:
    return "installed" if browser_available() else "not installed"


def crawl_with_browser(
    start_url: str,
    *,
    allow_private: bool,
    max_pages: int,
    max_depth: int = 3,
    storage_state: str | None = None,
    extra_headers: dict[str, str] | None = None,
    login: tuple[str, str, str] | None = None,  # (login_url, username, password)
) -> tuple[list[PageSnapshot], dict[str, Any]]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise BrowserUnavailable("The Playwright package is not installed.") from exc

    origin = origin_of(start_url)
    allowed_hosts: dict[tuple[str, str, int], bool] = {origin: True}

    def permitted(url: str) -> bool:
        scheme = urlparse(url).scheme
        if scheme in {"data", "blob", "about"}:
            return True
        if scheme not in {"http", "https"}:
            return False
        key = origin_of(url)
        if key not in allowed_hosts:
            try:
                validate_target(f"{key[0]}://{key[1]}:{key[2]}", allow_private)
                allowed_hosts[key] = True
            except (TargetRejected, ValueError):
                allowed_hosts[key] = False
        return allowed_hosts[key]

    snapshots: list[PageSnapshot] = []
    errors: list[str] = []
    scripts: dict[str, str] = {}
    visited = 0
    try:
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(headless=True)
            except Exception as exc:  # missing browser binary or sandbox failure
                raise BrowserUnavailable(f"Chromium could not be launched: {str(exc).splitlines()[0][:160]}") from exc
            context_args: dict[str, Any] = {"extra_http_headers": extra_headers or {}}
            if storage_state:
                context_args["storage_state"] = storage_state
            context = browser.new_context(**context_args)
            context.route("**/*", lambda route: route.continue_() if permitted(route.request.url) else route.abort())
            page = context.new_page()
            console: list[str] = []
            requests: list[str] = []
            page.on("console", lambda msg: console.append(msg.text) if msg.type in {"error", "warning"} else None)
            page.on("request", lambda req: requests.append(req.url))

            def capture_script(response: Any) -> None:
                try:
                    if response.request.resource_type == "script" and origin_of(response.url) == origin and len(scripts) < 10:
                        scripts[response.url] = response.text()[:MAX_SCRIPT_CHARS]
                except Exception:
                    return

            page.on("response", capture_script)

            if login:
                login_url, username, password = login
                page.goto(login_url, timeout=NAV_TIMEOUT_MS, wait_until="networkidle")
                page.fill("input[type=password]", password)
                page.fill("input[type=email], input[type=text], input:not([type])", username)
                page.keyboard.press("Enter")
                page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT_MS)

            queue: deque[tuple[str, int]] = deque([(urldefrag(start_url)[0], 0)])
            seen = {urldefrag(start_url)[0]}
            while queue and visited < max_pages:
                url, depth = queue.popleft()
                console.clear()
                requests.clear()
                try:
                    response = page.goto(url, timeout=NAV_TIMEOUT_MS, wait_until="networkidle")
                except Exception as exc:
                    errors.append(f"{url[:120]}: {exc.__class__.__name__}")
                    continue
                visited += 1
                if response is None or origin_of(page.url) != origin:
                    continue
                headers = {k.lower(): v for k, v in response.all_headers().items()}
                html = page.content()
                snap = PageSnapshot(url=page.url, status=response.status, headers=headers, body=html, engine="browser")
                snap.cookies = [parse_set_cookie(h, page.url) for h in response.header_values("set-cookie")]
                for cookie in context.cookies():
                    if not any(c.name == cookie["name"] for c in snap.cookies):
                        snap.cookies.append(CookieInfo(
                            cookie["name"][:100], bool(cookie.get("secure")), bool(cookie.get("httpOnly")),
                            (cookie.get("sameSite") or None), page.url))
                snap.console_errors = list(console)
                snap.requests = list(requests)
                try:
                    snap.storage = page.evaluate(
                        "() => ({localStorage: Object.keys(localStorage), sessionStorage: Object.keys(sessionStorage)})")
                except Exception:
                    snap.storage = {}
                snapshots.append(snap)
                if depth >= max_depth:
                    continue
                for link in parse_html(html, page.url).links:
                    link = urldefrag(link)[0]
                    path = urlparse(link).path.lower()
                    if (urlparse(link).scheme in {"http", "https"} and origin_of(link) == origin and link not in seen
                            and not path.endswith(STATIC_EXTENSIONS) and not SKIP_PATH.search(path)):
                        seen.add(link)
                        queue.append((link, depth + 1))
            context.close()
            browser.close()
    except BrowserUnavailable:
        raise
    except Exception as exc:
        raise BrowserUnavailable(f"The browser session failed: {str(exc).splitlines()[0][:160]}") from exc

    for src, body in scripts.items():
        snapshots.append(PageSnapshot(url=src, status=200, headers={"content-type": "application/javascript"}, body=body,
                                      kind="script", engine="browser"))
    pages = [s for s in snapshots if s.kind == "page"]
    stats = {
        "engine": "browser", "pages_visited": visited, "pages_analyzed": len(pages), "scripts_fetched": len(scripts),
        "forms_found": sum(len(s.parsed().forms) for s in pages), "errors": errors[:5], "max_pages": max_pages,
        "max_depth": max_depth,
    }
    return snapshots, stats
