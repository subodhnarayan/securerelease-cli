"""Intentionally weak UI used to validate the UI scanner. Never deploy.

Run: python tests/fixtures/mini_ui/server.py 8766

Intentional weaknesses: no security headers, weak cookies, a login form without CSRF token
that submits a password over GET, third-party script without SRI, hard-coded secret and a
sensitive HTML comment, reflected input, open redirect, exposed .env and source map.
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

INDEX = """<!doctype html><html><head><title>Mini UI</title>
<!-- TODO: remove admin password before launch -->
<meta name="generator" content="MiniCMS 1.0">
<script src="https://cdn.example.test/lib.js"></script>
<script src="/static/app.js"></script>
<script>var config = {api_key: "sk_live_abcdef1234567890"}; </script>
</head><body onload="init()">
<a href="/login">Login</a> <a href="/search?q=hello">Search</a> <a href="/go?next=https://example.org/">Go</a>
<a href="/logout">Logout</a>
<img src="http://assets.example.test/logo.png">
<form method="post" action="/comment"><input name="text"><input type="submit"></form>
</body></html>"""
LOGIN = """<!doctype html><html><body><form method="get" action="/session">
<input type="text" name="user"><input type="password" name="pass"><input type="submit"></form></body></html>"""
APP_JS = "console.log('app');\n//# sourceMappingURL=app.js.map\n"


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, content_type="text/html", extra=None):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Server", "Apache/2.4.1")
        self.send_header("Set-Cookie", "sessionid=abc123def456; Path=/")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/":
            return self._send(200, INDEX)
        if path == "/login":
            return self._send(200, LOGIN)
        if path == "/search":
            return self._send(200, f"<html><body>Results for {parse_qs(parsed.query).get('q', [''])[0]}</body></html>")
        if path == "/go":
            target = parse_qs(parsed.query).get("next", ["/"])[0]
            return self._send(302, "", extra={"Location": target})
        if path == "/static/app.js":
            return self._send(200, APP_JS, "application/javascript")
        if path == "/static/app.js.map":
            return self._send(200, '{"version":3,"mappings":"AAAA","sources":["app.ts"]}', "application/json")
        if path == "/.env":
            return self._send(200, "DB_PASSWORD=hunter2hunter2\nSECRET_KEY=abc", "text/plain")
        if path == "/logout":
            return self._send(200, "<html>bye</html>")
        self._send(404, "<html>not found</html>")

    def do_POST(self):
        self._send(200, "<html>ok</html>")

    def log_message(self, *args):
        return


def make_server(port=0):
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    make_server(int(sys.argv[1]) if len(sys.argv) > 1 else 8766).serve_forever()
