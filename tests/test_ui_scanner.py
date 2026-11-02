import importlib.util

import httpx
import pytest
from conftest import by_id

from securerelease.scanners.ui_checks import analyze
from securerelease.scanners.ui_scanner import scan_ui
from securerelease.scanners.ui_snapshot import PageSnapshot, parse_html, parse_set_cookie

ENV = {"UI_USER": "alice", "UI_PASS": "s3cret-pass", "UI_COOKIE": "Cookie: session=abc999xyz"}


def run(url, **kwargs):
    kwargs.setdefault("allow_private", True)
    kwargs.setdefault("engine", "crawler")
    kwargs.setdefault("env", ENV)
    findings, _ = scan_ui(url, **kwargs)
    return findings, by_id(findings)


def test_passive_scan_reports_expected_weaknesses(mini_ui_url):
    findings, found = run(mini_ui_url)
    assert found["UI-COVERAGE"].evidence["pages_analyzed"] == 3
    assert found["UI-CSP-HEADER"].status == "WARN"
    assert found["UI-CLICKJACKING"].status == "WARN"
    assert found["UI-COOKIES"].status == "WARN" and found["UI-COOKIES"].severity == "MEDIUM"
    assert found["UI-FORM-PASSWORD-GET"].status == "FAIL"
    assert found["UI-FORM-CSRF"].status == "WARN"
    assert found["UI-SRI"].status == "WARN"
    assert found["UI-SECRETS"].status == "FAIL"
    assert found["UI-HTML-COMMENTS"].status == "WARN"
    assert found["UI-SOURCE-MAPS"].status == "WARN"
    assert found["UI-EXPOSED-PATHS"].status == "FAIL" and found["UI-EXPOSED-PATHS"].severity == "CRITICAL"
    assert found["UI-OPEN-REDIRECT-PARAM"].status == "WARN"
    assert not any(f.status == "ERROR" for f in findings)


def test_secret_values_are_masked(mini_ui_url):
    _, found = run(mini_ui_url)
    evidence = str(found["UI-SECRETS"].evidence) + str(found["UI-EXPOSED-PATHS"].evidence)
    assert "abcdef1234567890" not in evidence and "hunter2" not in evidence and "sk_l***" in evidence


def test_crawler_skips_logout_like_links(mini_ui_url):
    from securerelease.scanners.safe_http import SafeClient
    from securerelease.scanners.ui_crawler import crawl

    with SafeClient(mini_ui_url, allow_private=True, persist_cookies=True) as client:
        snapshots, _ = crawl(client, mini_ui_url)
    visited = {s.url for s in snapshots}
    assert not any(url.endswith("/logout") for url in visited) and any(url.endswith("/login") for url in visited)


def test_active_probes_require_authorized(mini_ui_url):
    _, found = run(mini_ui_url)
    assert found["UI-ACTIVE-PROBES"].status == "NOT_TESTED" and "--authorized" in found["UI-ACTIVE-PROBES"].summary
    assert "UI-REFLECTED-INPUT" not in found and "UI-OPEN-REDIRECT" not in found


def test_authorized_probes_find_reflection_and_open_redirect(mini_ui_url):
    _, found = run(mini_ui_url, authorized=True)
    assert found["UI-REFLECTED-INPUT"].status == "WARN"
    assert found["UI-OPEN-REDIRECT"].status == "FAIL"


def test_max_pages_limits_the_crawl(mini_ui_url):
    _, found = run(mini_ui_url, max_pages=1)
    assert found["UI-COVERAGE"].evidence["pages_visited"] == 1 and found["UI-COVERAGE"].status == "WARN"


def test_scripted_login_posts_credentials_without_reporting_them(mini_ui_url):
    findings, found = run(mini_ui_url, login_url=mini_ui_url + "/login", user_env="UI_USER", pass_env="UI_PASS")
    login = found["UI-AUTH-LOGIN"]
    assert login.status == "PASS" and login.evidence["cookies_set"] >= 1
    assert "s3cret-pass" not in repr([f.to_dict() for f in findings])
<<<<<<< HEAD
=======
    assert found["UI-COVERAGE"].evidence["authenticated"] is True


def test_browser_login_failure_is_an_auth_error(monkeypatch):
    from securerelease.scanners.ui_browser import BrowserLoginFailed

    def fail(*args, **kwargs):
        raise BrowserLoginFailed("The UI target redirected back to the login page.")

    monkeypatch.setattr("securerelease.scanners.ui_scanner.crawl_with_browser", fail)
    findings, versions = scan_ui(
        "http://127.0.0.1:9/dashboard", allow_private=True, engine="browser",
        login_url="http://127.0.0.1:9/login", user_env="UI_USER", pass_env="UI_PASS", env=ENV,
    )
    assert [f.check_id for f in findings] == ["UI-AUTH-LOGIN"]
    assert findings[0].status == "ERROR"
    assert versions == {"ui-engine": "playwright"}
    assert "s3cret-pass" not in repr([f.to_dict() for f in findings])


def test_browser_login_verified_in_coverage(monkeypatch):
    def crawl(*args, **kwargs):
        return [snapshot("http://127.0.0.1:9/dashboard", "<html>Dashboard</html>")], {
            "engine": "browser", "pages_analyzed": 1, "login_verified": True,
        }

    monkeypatch.setattr("securerelease.scanners.ui_scanner.crawl_with_browser", crawl)
    findings, _ = scan_ui(
        "http://127.0.0.1:9/dashboard", allow_private=True, engine="browser",
        login_url="http://127.0.0.1:9/login", user_env="UI_USER", pass_env="UI_PASS", env=ENV,
        transport=httpx.MockTransport(lambda request: httpx.Response(404)),
    )
    found = by_id(findings)
    assert found["UI-AUTH-LOGIN"].status == "PASS"
    assert found["UI-COVERAGE"].evidence["authenticated"] is True
>>>>>>> dce590a (updated version of cli)


def test_auth_header_is_sent_and_redacted():
    seen = []

    def handler(request):
        seen.append(request.headers.get("cookie"))
        return httpx.Response(200, text="<html><body>session=abc999xyz</body></html>", headers={"content-type": "text/html"})

    findings, _ = scan_ui("http://127.0.0.1:9", allow_private=True, engine="crawler", auth_header_env="UI_COOKIE",
                          transport=httpx.MockTransport(handler), env=ENV)
    assert seen and all(c == "session=abc999xyz" for c in seen)
    assert "abc999xyz" not in repr([f.to_dict() for f in findings])
<<<<<<< HEAD
=======
    assert by_id(findings)["UI-COVERAGE"].evidence["authentication_configured"] is True
    assert by_id(findings)["UI-COVERAGE"].evidence["authenticated"] is False
>>>>>>> dce590a (updated version of cli)


def test_spa_catch_all_does_not_trigger_exposed_path_false_positive():
    html = "<html><head><title>App</title></head><body><div id=root></div></body></html>"
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text=html, headers={"content-type": "text/html"}))
    findings, _ = scan_ui("http://127.0.0.1:9", allow_private=True, engine="crawler", transport=transport)
    assert by_id(findings)["UI-EXPOSED-PATHS"].status == "PASS"


def test_unreachable_ui_is_a_coverage_gap():
    findings, _ = scan_ui("http://127.0.0.1:1", allow_private=True, engine="crawler")
    assert [f.check_id for f in findings] == ["HTTP-CONNECTIVITY"]


def test_private_target_policy_applies():
    findings, _ = scan_ui("http://127.0.0.1:8000", engine="crawler")
    assert findings[0].check_id == "TARGET-POLICY"


@pytest.mark.skipif(importlib.util.find_spec("playwright") is not None, reason="Playwright is installed")
def test_browser_engine_missing_is_not_a_pass(mini_ui_url):
    findings, _ = scan_ui(mini_ui_url, allow_private=True, engine="browser")
    assert [f.check_id for f in findings] == ["TOOL-PLAYWRIGHT-MISSING"] and findings[0].status == "NOT_TESTED"


def test_auto_engine_falls_back_to_crawler(mini_ui_url):
    if importlib.util.find_spec("playwright") is not None:
        pytest.skip("Playwright is installed")
    _, found = run(mini_ui_url, engine="auto")
    assert found["UI-COVERAGE"].evidence["engine"] == "crawler"


def snapshot(url, body="", headers=None, **kwargs):
    return PageSnapshot(url=url, status=200, headers={"content-type": "text/html", **(headers or {})}, body=body, **kwargs)


def test_mixed_content_https_page():
    page = snapshot("https://app.test/", '<script src="http://cdn.test/a.js"></script><img src="http://cdn.test/i.png">')
    found = by_id(analyze([page], "https://app.test/"))
    assert found["UI-HTTPS"].status == "PASS" and found["UI-MIXED-CONTENT"].status == "FAIL"
    assert found["UI-HSTS"].status == "WARN"


def test_strong_headers_pass_and_weak_csp_warns():
    strong = {"content-security-policy": "default-src 'self'; frame-ancestors 'none'", "strict-transport-security": "max-age=1",
              "x-content-type-options": "nosniff", "referrer-policy": "no-referrer"}
    found = by_id(analyze([snapshot("https://app.test/", "<html></html>", strong)], "https://app.test/"))
    assert all(found[c].status == "PASS" for c in ("UI-CSP-HEADER", "UI-HSTS", "UI-NOSNIFF", "UI-CLICKJACKING", "UI-CSP-QUALITY"))
    weak = {"content-security-policy": "script-src 'unsafe-inline' 'unsafe-eval' *"}
    assert by_id(analyze([snapshot("https://app.test/", "", weak)], "https://app.test/"))["UI-CSP-QUALITY"].status == "WARN"


def test_password_form_over_http_to_public_host_fails():
    page = snapshot("http://app.example.test/", '<form method="post" action="http://app.example.test/login">'
                    '<input type="password" name="p"><input type="hidden" name="csrf_token" value="x"></form>')
    found = by_id(analyze([page], "http://app.example.test/"))
    assert found["UI-FORM-PASSWORD-HTTP"].status == "FAIL" and found["UI-FORM-CSRF"].status == "PASS"
    assert found["UI-HTTPS"].status == "FAIL"


def test_browser_snapshot_storage_and_cookies():
    page = snapshot("https://app.test/", "<html></html>", engine="browser", storage={"localStorage": ["auth_token", "theme"]})
    page.cookies = [parse_set_cookie("sid=1; Secure; HttpOnly; SameSite=Lax", page.url)]
    found = by_id(analyze([page], "https://app.test/"))
    assert found["UI-STORAGE"].status == "WARN" and "theme" not in str(found["UI-STORAGE"].evidence)
    assert found["UI-COOKIES"].status == "PASS"


def test_parser_tolerates_malformed_html():
    parsed = parse_html("<form><input type=password name=p><a href='/x'<<<>", "https://a.test/")
    assert parsed.forms and parsed.forms[0]["inputs"][0]["type"] == "password"
