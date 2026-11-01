"""A guarded HTTP client shared by the API and UI scanners.

Every request is checked against the target policy, kept inside the original
origin, counted against a request budget, and limited to a capped response body.
Redirects are never followed automatically. Methods other than GET/HEAD/OPTIONS
are refused unless the caller opted in.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from securerelease.auth import redact
from securerelease.scanners.http_baseline import USER_AGENT, tls_verify, validate_target

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
DEFAULT_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
DEFAULT_MAX_BODY = 256 * 1024


class BudgetExceeded(Exception):
    """The per-target request budget has been used up."""


class ScopeViolation(ValueError):
    """A request left the approved origin or used a method that was not enabled."""


@dataclass(slots=True)
class Reply:
    url: str
    method: str
    status: int
    headers: httpx.Headers
    body: str
    truncated: bool
    elapsed: float

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()

    @property
    def set_cookies(self) -> list[str]:
        return self.headers.get_list("set-cookie")

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self) -> Any:
        try:
            return json.loads(self.body)
        except ValueError:
            return None


def origin_of(url: str) -> tuple[str, str, int]:
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.scheme, (parsed.hostname or "").lower(), port


class SafeClient:
    def __init__(
        self,
        base_url: str,
        *,
        allow_private: bool = False,
        max_requests: int = 300,
        headers: dict[str, str] | None = None,
        secrets: list[str] | None = None,
        allow_mutating: bool = False,
        persist_cookies: bool = False,
        transport: httpx.BaseTransport | None = None,
        timeout: httpx.Timeout = DEFAULT_TIMEOUT,
    ) -> None:
        # Raises TargetRejected when the target violates the safe-default policy.
        self.base_url = validate_target(base_url, allow_private)
        self.allow_private = allow_private
        self.max_requests = max_requests
        self.requests_made = 0
        self.default_headers = dict(headers or {})
        self.secrets = list(secrets or [])
        self.allow_mutating = allow_mutating
        self.persist_cookies = persist_cookies
        self._origin = origin_of(self.base_url)
        self._validated = {self._origin}
        self._http = httpx.Client(
            timeout=timeout, follow_redirects=False, verify=tls_verify(), transport=transport,
            headers={"User-Agent": USER_AGENT},
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "SafeClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def remaining(self) -> int:
        return max(0, self.max_requests - self.requests_made)

    def add_secret(self, *values: str) -> None:
        self.secrets.extend(v for v in values if v)

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        data: dict[str, str] | None = None,
        auth: bool = True,
        allow_unsafe: bool = False,
        max_body: int = DEFAULT_MAX_BODY,
    ) -> Reply:
        method = method.upper()
        if method not in SAFE_METHODS and not (self.allow_mutating or allow_unsafe):
            raise ScopeViolation(f"{method} requests are disabled; pass --allow-mutating to enable them.")
        if origin_of(url) != self._origin:
            raise ScopeViolation("The request target is outside the approved origin.")
        if self.requests_made >= self.max_requests:
            raise BudgetExceeded(f"Request budget of {self.max_requests} was reached.")
        if origin_of(url) not in self._validated:
            validate_target(url, self.allow_private)
            self._validated.add(origin_of(url))

        merged = dict(self.default_headers) if auth else {}
        merged.update(headers or {})
        self.requests_made += 1
        if not self.persist_cookies:
            self._http.cookies.clear()

        started = time.monotonic()
        with self._http.stream(method, url, headers=merged, params=params, json=json_body, data=data) as response:
            chunks: list[bytes] = []
            consumed = 0
            truncated = False
            for chunk in response.iter_bytes(chunk_size=4096):
                consumed += len(chunk)
                chunks.append(chunk)
                if consumed >= max_body:
                    truncated = True
                    break
            status, response_headers = response.status_code, response.headers
        raw = b"".join(chunks)[:max_body]
        return Reply(
            url=url, method=method, status=status, headers=response_headers,
            body=redact(raw.decode("utf-8", errors="replace"), self.secrets),
            truncated=truncated, elapsed=time.monotonic() - started,
        )

    def get(self, url: str, **kwargs: Any) -> Reply:
        return self.request("GET", url, **kwargs)
