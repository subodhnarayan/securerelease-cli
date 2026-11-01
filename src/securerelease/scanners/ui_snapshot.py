"""Engine-neutral page snapshots shared by the crawler and the browser engine."""
from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin


@dataclass(slots=True)
class CookieInfo:
    name: str
    secure: bool
    http_only: bool
    same_site: str | None
    url: str


def parse_set_cookie(header: str, url: str) -> CookieInfo:
    parts = [p.strip() for p in header.split(";")]
    lowered = [p.lower() for p in parts[1:]]
    same_site = next((p.split("=", 1)[1] for p in lowered if p.startswith("samesite=")), None)
    return CookieInfo(
        name=parts[0].split("=", 1)[0][:100], secure="secure" in lowered, http_only="httponly" in lowered,
        same_site=same_site, url=url,
    )


@dataclass(slots=True)
class PageSnapshot:
    url: str
    status: int
    headers: dict[str, str]
    body: str
    kind: str = "page"  # "page" or "script"
    engine: str = "crawler"
    cookies: list[CookieInfo] = field(default_factory=list)
    console_errors: list[str] = field(default_factory=list)
    requests: list[str] = field(default_factory=list)
    storage: dict[str, list[str]] = field(default_factory=dict)
    _parsed: "ParsedHtml | None" = None

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()

    @property
    def is_html(self) -> bool:
        return self.kind == "page" and ("html" in self.content_type or not self.content_type)

    def parsed(self) -> "ParsedHtml":
        if self._parsed is None:
            self._parsed = parse_html(self.body, self.url) if self.is_html else ParsedHtml()
        return self._parsed


@dataclass(slots=True)
class ParsedHtml:
    scripts: list[dict[str, Any]] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    resources: list[tuple[str, str]] = field(default_factory=list)  # (kind, absolute url)
    comments: list[str] = field(default_factory=list)
    generator: str | None = None
    inline_handlers: int = 0


class _Extractor(HTMLParser):
    def __init__(self, base: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base = base
        self.out = ParsedHtml()
        self._form: dict[str, Any] | None = None
        self._script: dict[str, Any] | None = None

    def _abs(self, value: str | None) -> str | None:
        return urljoin(self.base, value.strip()) if value and value.strip() else None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        self.out.inline_handlers += sum(1 for k in a if k.startswith("on") and len(k) > 2)
        if tag == "script":
            src = self._abs(a.get("src"))
            self._script = {"src": src, "integrity": a.get("integrity"), "inline": src is None, "text": ""}
            self.out.scripts.append(self._script)
        elif tag == "link" and a.get("href"):
            rel = a.get("rel", "").lower()
            href = self._abs(a["href"])
            if href and "stylesheet" in rel:
                self.out.resources.append(("stylesheet", href))
                self.out.scripts.append({"src": href, "integrity": a.get("integrity"), "inline": False, "text": "", "stylesheet": True})
        elif tag == "a" and a.get("href"):
            href = self._abs(a["href"])
            if href:
                self.out.links.append(href)
        elif tag == "form":
            self._form = {"action": self._abs(a.get("action")) or self.base, "method": (a.get("method") or "get").lower(), "inputs": []}
            self.out.forms.append(self._form)
        elif tag in {"input", "textarea", "select"} and self._form is not None:
            self._form["inputs"].append({
                "type": (a.get("type") or "text").lower() if tag == "input" else tag,
                "name": a.get("name", ""), "autocomplete": a.get("autocomplete", "").lower(), "value": a.get("value", ""),
            })
        elif tag in {"img", "iframe", "embed", "source", "audio", "video", "object", "frame"}:
            url = self._abs(a.get("src") or a.get("data"))
            if url:
                self.out.resources.append((tag, url))
        elif tag == "meta" and a.get("name", "").lower() == "generator":
            self.out.generator = a.get("content", "")[:100]
        if tag == "script" and a.get("src"):
            url = self._abs(a["src"])
            if url:
                self.out.resources.append(("script", url))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None
        elif tag == "script":
            self._script = None

    def handle_data(self, data: str) -> None:
        if self._script is not None and self._script["inline"]:
            self._script["text"] += data

    def handle_comment(self, data: str) -> None:
        self.out.comments.append(data.strip()[:300])


def parse_html(body: str, base: str) -> ParsedHtml:
    extractor = _Extractor(base)
    try:
        extractor.feed(body)
        extractor.close()
    except Exception:  # malformed markup must never abort a scan
        pass
    return extractor.out
