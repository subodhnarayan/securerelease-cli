import httpx
import pytest

from securerelease.scanners.http_baseline import TargetRejected, inspect_response, validate_target


def make_response(headers=None, status_code=200):
    request = httpx.Request("GET", "https://example.test/")
    return httpx.Response(status_code, headers=headers or {}, request=request)


def test_validate_target_requires_absolute_http_url():
    with pytest.raises(TargetRejected):
        validate_target("file:///etc/passwd")


def test_private_literal_rejected_by_default():
    with pytest.raises(TargetRejected):
        validate_target("http://127.0.0.1")


def test_private_literal_can_be_explicitly_allowed():
    assert validate_target("http://127.0.0.1:3000", allow_private=True) == "http://127.0.0.1:3000"


def test_https_headers_report_missing_csp():
    findings = inspect_response("https://example.test", "Website", make_response({"server": "test"}))
    csp = next(f for f in findings if f.check_id == "HTTP-CSP")
    https = next(f for f in findings if f.check_id == "HTTP-HTTPS")
    assert csp.status == "WARN"
    assert https.status == "PASS"


def test_http_hsts_is_not_tested():
    request = httpx.Request("GET", "http://example.test/")
    response = httpx.Response(200, request=request)
    findings = inspect_response("http://example.test", "Website", response)
    hsts = next(f for f in findings if f.check_id == "HTTP-HSTS")
    assert hsts.status == "NOT_TESTED"


def test_scan_url_against_explicitly_allowed_local_fixture():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    from securerelease.scanners.http_baseline import scan_url

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Set-Cookie", "sessionid=dummy; Secure; HttpOnly; SameSite=Lax")
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            try:
                self.wfile.write(b"fixture response")
            except BrokenPipeError:
                pass

        def do_OPTIONS(self):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "https://app.example.test")
            self.end_headers()

        def log_message(self, format, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}"
        findings = scan_url(url, allow_private=True)
        by_id = {item.check_id: item for item in findings}
        assert by_id["HTTP-HTTPS"].status == "WARN"
        assert by_id["HTTP-HTTPS"].severity == "INFO"
        assert by_id["HTTP-CSP"].status == "PASS"
        assert by_id["HTTP-CLICKJACKING"].status == "PASS"
        assert by_id["HTTP-COOKIE-1"].status == "PASS"
        assert by_id["HTTP-CORS-OBSERVATION"].status == "PASS"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
