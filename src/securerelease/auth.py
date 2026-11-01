"""Credential loading and redaction helpers.

Credentials are read from environment variables only, so they never appear on a
command line, in shell history, or in a report.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Mapping

REDACTED = "[REDACTED]"
MIN_SECRET_LENGTH = 4


class AuthError(ValueError):
    """Raised when requested credentials cannot be loaded."""


def _env_value(name: str, env: Mapping[str, str] | None = None) -> str:
    value = (env if env is not None else os.environ).get(name, "")
    if not value.strip():
        raise AuthError(f"Environment variable {name} is not set or is empty.")
    return value.strip()


def bearer_header_from_env(name: str, env: Mapping[str, str] | None = None) -> tuple[dict[str, str], list[str]]:
    """Return an Authorization header and the secret values to redact from output."""
    token = _env_value(name, env)
    scheme_given = token.lower().startswith(("bearer ", "basic ", "token "))
    return {"Authorization": token if scheme_given else f"Bearer {token}"}, _secrets_of(token)


def header_from_env(name: str, env: Mapping[str, str] | None = None) -> tuple[dict[str, str], list[str]]:
    """Parse an environment variable containing `Header-Name: value`."""
    raw = _env_value(name, env)
    header, sep, value = raw.partition(":")
    header, value = header.strip(), value.strip()
    if not sep or not header or not value or any(c in header for c in " \t\r\n"):
        raise AuthError(f"Environment variable {name} must contain 'Header-Name: value'.")
    if "\r" in value or "\n" in value:
        raise AuthError(f"Environment variable {name} contains a line break.")
    return {header: value}, _secrets_of(value)


def _secrets_of(value: str) -> list[str]:
    parts = {value}
    if " " in value:
        parts.add(value.split(" ", 1)[1])
    return [p for p in parts if len(p) >= MIN_SECRET_LENGTH]


def credentials_from_env(
    user_env: str | None, password_env: str | None, env: Mapping[str, str] | None = None
) -> tuple[str, str]:
    if not user_env or not password_env:
        raise AuthError("Both a username and a password environment variable name are required.")
    return _env_value(user_env, env), _env_value(password_env, env)


def cookies_from_storage_state(path: str | Path, host: str) -> tuple[dict[str, str], list[str]]:
    """Read cookies applicable to `host` from a Playwright storage-state file."""
    try:
        data = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise AuthError(f"Could not read the storage-state file: {exc.__class__.__name__}.") from exc
    cookies: dict[str, str] = {}
    secrets: list[str] = []
    for item in data.get("cookies", []) if isinstance(data, dict) else []:
        domain = str(item.get("domain", "")).lstrip(".").lower()
        if domain and (host == domain or host.endswith("." + domain)):
            cookies[str(item.get("name", ""))] = str(item.get("value", ""))
            secrets.extend(_secrets_of(str(item.get("value", ""))))
    return {k: v for k, v in cookies.items() if k}, secrets


def redact(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        if len(secret) >= MIN_SECRET_LENGTH:
            text = text.replace(secret, REDACTED)
    return text
