"""Interactive `securerelease init`: asks a few questions and writes a .env file."""
from __future__ import annotations

import getpass
import os
from pathlib import Path
from typing import Callable

FORBIDDEN = ('"', "\n", "\r")


def _quote(value: str) -> str:
    return f'"{value}"' if any(c in value for c in " #'") else value


def _ask(prompt: str, input_fn: Callable[[str], str], validate: Callable[[str], str | None] | None = None,
         out: Callable[[str], None] = print) -> str:
    while True:
        answer = input_fn(prompt).strip()
        if any(c in answer for c in FORBIDDEN):
            out("  Please avoid double quotes and line breaks.")
            continue
        problem = validate(answer) if (validate and answer) else None
        if problem:
            out(f"  {problem}")
            continue
        return answer


def _hidden(prompt: str, secret_fn: Callable[[str], str], out: Callable[[str], None]) -> str:
    while True:
        value = secret_fn(prompt).strip()
        if any(c in value for c in FORBIDDEN):
            out("  Please avoid double quotes and line breaks.")
            continue
        return value


def _yes(prompt: str, input_fn: Callable[[str], str], default: bool = False) -> bool:
    answer = input_fn(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    return default if not answer else answer in {"y", "yes"}


def _http_url(value: str) -> str | None:
    return None if value.lower().startswith(("http://", "https://")) else "Enter a full URL starting with http:// or https://"


def run_init(
    path: str = ".env",
    *,
    input_fn: Callable[[str], str] = input,
    secret_fn: Callable[[str], str] = getpass.getpass,
    out: Callable[[str], None] = print,
) -> int:
    target = Path(path).expanduser()
    out("SecureRelease setup. Press Enter to skip any question. Secrets are typed hidden and saved only to " + str(target) + ".")
    if target.exists() and not _yes(f"{target} already exists. Overwrite it?", input_fn):
        out("Nothing changed.")
        return 1

    ui_url = _ask("Website / UI URL (e.g. https://staging.example.com): ", input_fn, _http_url, out)
    api_url = _ask("API base URL (e.g. https://api.staging.example.com): ", input_fn, _http_url, out)
    spec = _ask("OpenAPI spec file path or URL (Enter to auto-discover): ", input_fn, None, out) if api_url else ""
    source = _ask("Repository folder to scan for secrets and vulnerable code (e.g. .): ", input_fn, None, out)
    if not (ui_url or api_url or source):
        out("Nothing to scan: give at least a UI URL, an API URL or a repository folder.")
        return 1

    token_a = token_b = login_url = username = password = ""
    if api_url and _yes("Does the API need a token for a test user?", input_fn):
        token_a = _hidden("  API token for test user A (hidden): ", secret_fn, out)
        if token_a and _yes("  Add a second test user to check object-level authorization (BOLA/IDOR)?", input_fn):
            token_b = _hidden("  API token for test user B (hidden): ", secret_fn, out)
    if ui_url and _yes("Does the website need a login?", input_fn):
        login_url = _ask("  Login page URL: ", input_fn, _http_url, out)
        username = _ask("  Test username: ", input_fn, None, out)
        password = _hidden("  Test password (hidden): ", secret_fn, out)
    private = any(u.startswith(("http://localhost", "http://127.", "https://localhost")) for u in (ui_url, api_url))
    private = _yes("Are the targets on localhost or a private network that you own?", input_fn, default=private)
    authorized = _yes(
        "Allow active tests (fuzzing, rate-limit burst, authorization replay)? Only say yes for systems you own", input_fn)

    lines = ["# Created by 'securerelease init'. Never commit this file: it may contain secrets.", ""]

    def add(key: str, value: str, comment: str = "") -> None:
        if value:
            lines.append(f"{key}={_quote(value)}" + (f"  # {comment}" if comment else ""))

    add("SECURERELEASE_UI_URL", ui_url)
    add("SECURERELEASE_API_URL", api_url)
    add("SECURERELEASE_OPENAPI_SPEC", spec)
    add("SECURERELEASE_SOURCE", source)
    lines.append("")
    add("SECURERELEASE_API_TOKEN", token_a)
    add("SECURERELEASE_API_TOKEN_B", token_b)
    add("SECURERELEASE_UI_LOGIN_URL", login_url)
    add("SECURERELEASE_UI_USERNAME", username)
    add("SECURERELEASE_UI_PASSWORD", password)
    lines += ["", f"SECURERELEASE_ALLOW_PRIVATE_TARGETS={'true' if private else 'false'}",
              f"SECURERELEASE_AUTHORIZED={'true' if authorized else 'false'}", ""]

    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
    os.chmod(target, 0o600)
    out(f"\nSaved {target} (owner-only permissions). Run the scan with:\n  securerelease run")
    return 0
