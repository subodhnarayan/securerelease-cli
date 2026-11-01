"""Exercises the Playwright engine logic with a minimal in-memory fake of playwright.sync_api."""
import sys
import types

import pytest

from securerelease.scanners.ui_browser import BrowserUnavailable, crawl_with_browser
from securerelease.scanners.ui_checks import analyze

PAGES = {
    "http://127.0.0.1:9/": '<html><a href="/two">two</a><a href="/logout">out</a><a href="https://elsewhere.test/">x</a></html>',
    "http://127.0.0.1:9/two": "<html><body>two</body></html>",
}


class FakeResponse:
    status = 200

    def all_headers(self):
        return {"Content-Type": "text/html", "X-Frame-Options": "DENY"}

    def header_values(self, name):
        return ["sid=1; Secure; HttpOnly; SameSite=Lax"]


class FakePage:
    def __init__(self):
        self.url = ""
        self.visited = []
        self.keyboard = types.SimpleNamespace(press=lambda key: None)

    def on(self, event, handler):
        pass

    def goto(self, url, **kwargs):
        self.url = url
        self.visited.append(url)
        return FakeResponse()

    def content(self):
        return PAGES.get(self.url, "<html></html>")

    def evaluate(self, script):
        return {"localStorage": ["jwt_token"], "sessionStorage": []}

    def fill(self, selector, value):
        pass

    def wait_for_load_state(self, *args, **kwargs):
        pass


class FakeContext:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.page = FakePage()

    def route(self, pattern, handler):
        pass

    def new_page(self):
        return self.page

    def cookies(self):
        return [{"name": "theme", "secure": False, "httpOnly": False, "sameSite": "None"}]

    def close(self):
        pass


class FakePlaywright:
    contexts = []

    def __enter__(self):
        outer = self
        self.chromium = types.SimpleNamespace(launch=lambda headless=True: types.SimpleNamespace(
            new_context=lambda **kw: outer._context(kw), close=lambda: None))
        return self

    def __exit__(self, *exc):
        return False

    def _context(self, kwargs):
        context = FakeContext(**kwargs)
        FakePlaywright.contexts.append(context)
        return context


@pytest.fixture
def fake_playwright(monkeypatch):
    package = types.ModuleType("playwright")
    sync_api = types.ModuleType("playwright.sync_api")
    sync_api.sync_playwright = lambda: FakePlaywright()
    monkeypatch.setitem(sys.modules, "playwright", package)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)
    FakePlaywright.contexts.clear()


def test_browser_crawl_stays_in_origin_and_collects_signals(fake_playwright):
    snapshots, stats = crawl_with_browser("http://127.0.0.1:9/", allow_private=True, max_pages=5,
                                          storage_state="state.json", extra_headers={"X-Test": "1"})
    visited = FakePlaywright.contexts[0].page.visited
    assert visited == ["http://127.0.0.1:9/", "http://127.0.0.1:9/two"]
    assert stats["engine"] == "browser" and stats["pages_visited"] == 2
    assert FakePlaywright.contexts[0].kwargs["storage_state"] == "state.json"
    found = {f.check_id: f for f in analyze(snapshots, "http://127.0.0.1:9/")}
    assert found["UI-STORAGE"].status == "WARN"
    assert found["UI-CLICKJACKING"].status == "PASS"


def test_browser_launch_failure_is_reported_as_unavailable(monkeypatch, fake_playwright):
    def boom(headless=True):
        raise RuntimeError("Executable doesn't exist at /x")

    monkeypatch.setattr(FakePlaywright, "__enter__", lambda self: types.SimpleNamespace(chromium=types.SimpleNamespace(launch=boom)))
    with pytest.raises(BrowserUnavailable, match="could not be launched"):
        crawl_with_browser("http://127.0.0.1:9/", allow_private=True, max_pages=1)
