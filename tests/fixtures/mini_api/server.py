"""Tiny intentionally weak API used to validate the API scanner and OpenAPI-driven DAST. Never deploy.

Run: python tests/fixtures/mini_api/server.py 8765

Intentional weaknesses:
  * GET /users/{id}      - broken object-level authorization (any valid token reads any user)
  * GET /admin/stats     - declared as secured in openapi.json but requires no authentication
  * GET /items/{id}      - a non-numeric id crashes with a leaked Python traceback (HTTP 500)
  * GET /search?q=       - reflects input; CORS reflects any Origin with credentials on /users*
  * no rate limiting anywhere
Secure reference behavior: GET /accounts/{id} enforces ownership.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

TOKENS = {"token-alice": 1, "token-bob": 2}
USERS = {1: {"id": 1, "name": "alice", "email": "alice@example.test"}, 2: {"id": 2, "name": "bob", "email": "bob@example.test"}}
SPEC = Path(__file__).with_name("openapi.json").read_text()


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, payload, *, content_type="application/json", extra=None):
        body = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Server", "mini-api/0.0.1")
        origin = self.headers.get("Origin")
        if origin and urlparse(self.path).path.startswith("/users"):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        else:
            self.send_header("Access-Control-Allow-Origin", "*")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _user(self):
        header = self.headers.get("Authorization", "")
        return TOKENS.get(header[7:].strip()) if header.startswith("Bearer ") else None

    def do_OPTIONS(self):
        self._send(204, "", extra={"Allow": "GET, POST, OPTIONS, TRACE"})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        last = path.rsplit("/", 1)[-1]
        if path == "/openapi.json":
            return self._send(200, SPEC)
        if path == "/health":
            return self._send(200, {"status": "ok"})
        if path.startswith("/items/"):
            if not last.isdigit():
                trace = 'Traceback (most recent call last):\n  File "app.py", line 12, in get_item\nValueError: invalid literal for int()'
                return self._send(500, trace, content_type="text/plain")
            return self._send(200, {"id": int(last), "name": "widget"})
        if path == "/search":
            return self._send(200, {"query": parse_qs(parsed.query).get("q", [""])[0], "results": []})
        if path == "/admin/stats":
            return self._send(200, {"users": len(USERS)})
        caller = self._user()
        if path in ("/users", "/accounts") or path.startswith(("/users/", "/accounts/")):
            if caller is None:
                return self._send(401, {"error": "unauthorized"})
            if path == "/users":
                return self._send(200, {"items": [USERS[caller]]})
            if path.startswith("/users/"):
                user = USERS.get(int(last)) if last.isdigit() else None
                return self._send(200, user) if user else self._send(404, {"error": "not found"})
            if not last.isdigit() or int(last) != caller:
                return self._send(403, {"error": "forbidden"})
            return self._send(200, USERS[caller])
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if self._user() is None:
            return self._send(401, {"error": "unauthorized"})
        self._send(201, {"id": 99})

    def log_message(self, *args):
        return


def make_server(port=0):
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    make_server(int(sys.argv[1]) if len(sys.argv) > 1 else 8765).serve_forever()
