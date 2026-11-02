"""Exercises the Playwright engine logic with a minimal in-memory fake of playwright.sync_api."""
import sys
import types

import pytest

<<<<<<< HEAD
from securerelease.scanners.ui_browser import BrowserUnavailable, crawl_with_browser
=======
from securerelease.scanners.ui_browser import BrowserLoginFailed, BrowserUnavailable, crawl_with_browser
>>>>>>> dce590a (updated version of cli)
from securerelease.scanners.ui_checks import analyze

PAGES = {
    "http://127.0.0.1:9/": '<html><a href="/two">two</a><a href="/logout">out</a><a href="https://elsewhere.test/">x</a></html>',
    "http://127.0.0.1:9/two": "<html><body>two</body></html>",
}


<<<<<<< HEAD
=======
class FakePlaywrightError(Exception):
    pass


>>>>>>> dce590a (updated version of cli)
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
<<<<<<< HEAD
=======
        self.login_waited = False
        self.password_visible = False
>>>>>>> dce590a (updated version of cli)
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

<<<<<<< HEAD
=======
    def locator(self, selector):
        page = self

        class Locator:
            def wait_for(self, **kwargs):
                page.login_waited = True

            def count(self):
                return int(page.password_visible)

        return Locator()

>>>>>>> dce590a (updated version of cli)

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
<<<<<<< HEAD
=======
    sync_api.Error = FakePlaywrightError
>>>>>>> dce590a (updated version of cli)
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
<<<<<<< HEAD
=======


def test_login_waits_for_form_to_disappear_before_reloading_target(fake_playwright, monkeypatch):
    original_goto = FakePage.goto

    def goto(page, url, **kwargs):
        if url.endswith("/two"):
            assert page.login_waited
        return original_goto(page, url, **kwargs)

    monkeypatch.setattr(FakePage, "goto", goto)
    _, stats = crawl_with_browser(
        "http://127.0.0.1:9/two", allow_private=True, max_pages=1,
        login=("http://127.0.0.1:9/login", "alice", "secret"),
    )
    assert stats["login_verified"] is True
    assert FakePlaywright.contexts[0].page.visited == [
        "http://127.0.0.1:9/login", "http://127.0.0.1:9/two", "http://127.0.0.1:9/two",
    ]


def test_rejected_login_is_not_reported_as_missing_browser(fake_playwright, monkeypatch):
    def locator(page, selector):
        def wait_for(**kwargs):
            raise FakePlaywrightError("Sensitive page contents must not be reported")
        return types.SimpleNamespace(wait_for=wait_for)

    monkeypatch.setattr(FakePage, "locator", locator)
    with pytest.raises(BrowserLoginFailed, match="Login did not complete") as exc:
        crawl_with_browser(
            "http://127.0.0.1:9/two", allow_private=True, max_pages=1,
            login=("http://127.0.0.1:9/login", "alice", "secret"),
        )
    assert "Sensitive" not in str(exc.value)


def test_login_session_must_survive_target_reload(fake_playwright, monkeypatch):
    original_goto = FakePage.goto

    def goto(page, url, **kwargs):
        response = original_goto(page, url, **kwargs)
        if url.endswith("/two"):
            page.url = "http://127.0.0.1:9/login"
        return response

    monkeypatch.setattr(FakePage, "goto", goto)
    with pytest.raises(BrowserLoginFailed, match="redirected back"):
        crawl_with_browser(
            "http://127.0.0.1:9/two", allow_private=True, max_pages=1,
            login=("http://127.0.0.1:9/login", "alice", "secret"),
        )


def test_password_form_after_reload_is_not_a_verified_session(fake_playwright, monkeypatch):
    original_goto = FakePage.goto

    def goto(page, url, **kwargs):
        page.password_visible = True
        return original_goto(page, url, **kwargs)

    monkeypatch.setattr(FakePage, "goto", goto)
    with pytest.raises(BrowserLoginFailed, match="password form remained"):
        crawl_with_browser(
            "http://127.0.0.1:9/two", allow_private=True, max_pages=1,
            login=("http://127.0.0.1:9/login", "alice", "secret"),
        )


def test_login_outside_target_origin_is_rejected(fake_playwright):
    with pytest.raises(BrowserLoginFailed, match="same origin"):
        crawl_with_browser(
            "http://127.0.0.1:9/two", allow_private=True, max_pages=1,
            login=("http://elsewhere.test/login", "alice", "secret"),
        )
    assert FakePlaywright.contexts[0].page.visited == []
>>>>>>> dce590a (updated version of cli)
