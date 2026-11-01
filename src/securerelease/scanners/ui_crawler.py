"""Lightweight same-origin crawler built on the guarded HTTP client."""
from __future__ import annotations

import re
from collections import deque
from typing import Any
from urllib.parse import urldefrag, urljoin, urlparse

import httpx

from securerelease.models import Finding
from securerelease.scanners.safe_http import BudgetExceeded, SafeClient, ScopeViolation, origin_of
from securerelease.scanners.ui_checks import SOURCE, snapshot_from_reply
from securerelease.scanners.ui_snapshot import PageSnapshot, parse_html

# Paths that could end a session or change state if a crawler followed them with GET.
SKIP_PATH = re.compile(r"log-?out|sign-?out|delete|remove|destroy|unsubscribe|deactivate|revoke", re.IGNORECASE)
STATIC_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".css", ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".zip", ".gz", ".mp4", ".mp3", ".map", ".js",
)
MAX_PAGE_BODY = 512 * 1024
MAX_SCRIPT_BODY = 1024 * 1024
MAX_SCRIPTS = 10


def _normalize(url: str) -> str:
    return urldefrag(url)[0]


def crawl(client: SafeClient, start_url: str, *, max_pages: int = 25, max_depth: int = 3) -> tuple[list[PageSnapshot], dict[str, Any]]:
    snapshots: list[PageSnapshot] = []
    queue: deque[tuple[str, int]] = deque([(_normalize(start_url), 0)])
    seen = {_normalize(start_url)}
    script_urls: list[str] = []
    errors: list[str] = []
    skipped_by_limit = 0
    visited = 0
    origin = origin_of(start_url)

    while queue:
        url, depth = queue.popleft()
        if visited >= max_pages:
            skipped_by_limit += 1 + len(queue)
            break
        try:
            reply = client.get(url, max_body=MAX_PAGE_BODY, headers={"Accept": "text/html,application/xhtml+xml,*/*;q=0.8"})
        except BudgetExceeded:
            break
        except (ScopeViolation, httpx.HTTPError) as exc:
            errors.append(f"{url[:120]}: {exc.__class__.__name__}")
            continue
        visited += 1
        if 300 <= reply.status < 400 and reply.headers.get("location"):
            snap = snapshot_from_reply(url, reply, kind="redirect")
            snapshots.append(snap)
            target = _normalize(urljoin(url, reply.headers["location"]))
            if origin_of(target) == origin and target not in seen:
                seen.add(target)
                queue.appendleft((target, depth))
            continue
        snap = snapshot_from_reply(url, reply)
        snapshots.append(snap)
        if not snap.is_html or reply.status >= 400:
            continue
        parsed = parse_html(reply.body, url)
        for script in parsed.scripts:
            src = script.get("src")
            if src and not script.get("stylesheet") and origin_of(src) == origin and src not in script_urls:
                script_urls.append(src)
        if depth >= max_depth:
            continue
        for link in parsed.links:
            link = _normalize(link)
            path = urlparse(link).path.lower()
            if (urlparse(link).scheme in {"http", "https"} and origin_of(link) == origin and link not in seen
                    and not path.endswith(STATIC_EXTENSIONS) and not SKIP_PATH.search(path)):
                seen.add(link)
                queue.append((link, depth + 1))

    for src in script_urls[:MAX_SCRIPTS]:
        try:
            reply = client.get(src, max_body=MAX_SCRIPT_BODY)
        except BudgetExceeded:
            break
        except (ScopeViolation, httpx.HTTPError):
            continue
        if reply.ok:
            snapshots.append(snapshot_from_reply(src, reply, kind="script"))

    pages = [s for s in snapshots if s.kind == "page"]
    stats = {
        "engine": "crawler", "pages_visited": visited, "pages_analyzed": len(pages),
        "scripts_fetched": sum(1 for s in snapshots if s.kind == "script"),
        "forms_found": sum(len(s.parsed().forms) for s in pages), "skipped_by_page_limit": skipped_by_limit,
        "errors": errors[:5], "max_pages": max_pages, "max_depth": max_depth,
    }
    return snapshots, stats


def login_with_form(client: SafeClient, login_url: str, username: str, password: str) -> Finding:
    """Submit the first password form found at `login_url`. Credentials are never reported."""
    client.add_secret(username, password)
    try:
        page = client.get(login_url, max_body=MAX_PAGE_BODY)
        forms = [f for f in parse_html(page.body, login_url).forms if any(i["type"] == "password" for i in f["inputs"])]
        if not forms:
            raise ValueError("no form with a password field was found")
        form = forms[0]
        data: dict[str, str] = {}
        username_set = False
        for field in form["inputs"]:
            name = field["name"]
            if not name:
                continue
            if field["type"] == "password":
                data[name] = password
            elif field["type"] in {"text", "email", "tel"} and not username_set:
                data[name], username_set = username, True
            elif field["type"] in {"hidden", "submit"}:
                data[name] = field["value"]
        if not username_set:
            raise ValueError("no username field was found")
        if origin_of(form["action"]) != origin_of(client.base_url):
            raise ValueError("the login form posts to a different origin")
        reply = client.request("POST", form["action"], data=data, allow_unsafe=True, max_body=MAX_PAGE_BODY)
    except (ValueError, ScopeViolation, BudgetExceeded, httpx.HTTPError) as exc:
        return Finding(
            check_id="UI-AUTH-LOGIN", title="UI: Scripted login", status="ERROR", severity="INFO", source=SOURCE, asset=login_url,
            summary="The scripted login could not be completed, so authenticated pages were not scanned.",
            evidence={"reason": str(exc)[:200]},
            remediation="Check --ui-login-url and the credential variables, or supply a Playwright storage-state file instead.",
        )
    cookies = len(client._http.cookies.jar)
    ok = reply.status < 400 and (cookies > 0 or 300 <= reply.status < 400)
    return Finding(
        check_id="UI-AUTH-LOGIN", title="UI: Scripted login", status="PASS" if ok else "ERROR", severity="INFO", source=SOURCE,
        asset=login_url,
        summary="The login form was submitted and a session was established." if ok else
        "The login form was submitted but no session cookie or redirect was observed; credentials may be wrong.",
        evidence={"status_code": reply.status, "cookies_set": cookies},
        remediation="Login success is inferred from cookies or redirects only; confirm that authenticated pages appear in the crawl coverage.",
    )
