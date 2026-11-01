"""Resolve scan settings from command-line flags, environment variables and a .env file.

Precedence (highest first): command-line flag > real environment variable > .env file > built-in default.
Secrets are never copied into settings. Only the *name* of the variable that holds a secret is passed on,
exactly like the --api-token-env style flags.
"""
from __future__ import annotations

import os
from argparse import Namespace
from pathlib import Path
from typing import MutableMapping

from securerelease.envfile import EnvFileError, apply_env, as_bool, load_env_file

DEFAULT_ENV_FILE = ".env"
PROFILES = ("baseline", "repository", "full", "dast", "api", "ui")

# attribute -> environment key, for plain values
TEXT_KEYS = {
    "url": "SECURERELEASE_UI_URL",
    "api_url": "SECURERELEASE_API_URL",
    "source": "SECURERELEASE_SOURCE",
    "openapi_spec": "SECURERELEASE_OPENAPI_SPEC",
    "ui_engine": "SECURERELEASE_UI_ENGINE",
    "ui_login_url": "SECURERELEASE_UI_LOGIN_URL",
    "ui_storage_state": "SECURERELEASE_UI_STORAGE_STATE",
    "report_format": "SECURERELEASE_FORMAT",
    "output": "SECURERELEASE_OUTPUT",
    "fail_on": "SECURERELEASE_FAIL_ON",
}
INT_KEYS = {"max_pages": "SECURERELEASE_MAX_PAGES", "max_requests": "SECURERELEASE_MAX_REQUESTS"}
BOOL_KEYS = {
    "authorized": "SECURERELEASE_AUTHORIZED",
    "allow_private_targets": "SECURERELEASE_ALLOW_PRIVATE_TARGETS",
    "allow_mutating": "SECURERELEASE_ALLOW_MUTATING",
    "no_fail_on_findings": "SECURERELEASE_NO_FAIL_ON_FINDINGS",
}
# attribute that holds an env-var *name* -> the variable the .env file is expected to define
SECRET_KEYS = {
    "api_token_env": "SECURERELEASE_API_TOKEN",
    "api_token_b_env": "SECURERELEASE_API_TOKEN_B",
    "api_auth_header_env": "SECURERELEASE_API_AUTH_HEADER",
    "ui_auth_header_env": "SECURERELEASE_UI_AUTH_HEADER",
    "ui_user_env": "SECURERELEASE_UI_USERNAME",
    "ui_pass_env": "SECURERELEASE_UI_PASSWORD",
}
# Targets are only taken from the environment when the chosen profile can use them.
PROFILE_TARGETS = {
    "ui": {"url"},
    "api": {"api_url", "openapi_spec"},
    "repository": {"source"},
    "baseline": {"url", "api_url"},
    "dast": {"url", "api_url", "openapi_spec"},
    "full": {"url", "api_url", "source", "openapi_spec"},
}
TARGET_ATTRS = {"url", "api_url", "source", "openapi_spec"}
FORMAT_EXTENSIONS = {"html": "html", "json": "json", "markdown": "md", "sarif": "sarif", "text": "txt"}


class ConfigError(ValueError):
    """The configuration is incomplete or invalid."""


def _unset(value: object) -> bool:
    return value is None or value is False or value == ""


def prepare(args: Namespace, command: str, environ: MutableMapping[str, str] | None = None) -> tuple[str, list[str]]:
    """Fill unset arguments from the environment and return (profile, summary lines)."""
    env = os.environ if environ is None else environ
    notes: list[str] = []
    explicit_file = getattr(args, "env_file", None)
    env_file = explicit_file or (DEFAULT_ENV_FILE if command == "run" else None)
    if env_file:
        try:
            applied = apply_env(load_env_file(env_file), env)
            notes.append(f"Config file : {Path(env_file).expanduser()} ({len(applied)} setting(s) loaded)")
        except EnvFileError as exc:
            if explicit_file or Path(env_file).expanduser().exists():
                raise ConfigError(str(exc)) from exc
            notes.append(f"Config file : none found at ./{env_file} (using flags and environment only)")
    use_environment = bool(env_file) or command == "run"

    if use_environment:
        profile = _profile_for(args, command, env)
        allowed_targets = PROFILE_TARGETS.get(profile, set())
        try:
            for attr, key in TEXT_KEYS.items():
                if attr in TARGET_ATTRS and attr not in allowed_targets:
                    continue
                if _unset(getattr(args, attr, None)) and env.get(key, "").strip():
                    setattr(args, attr, env[key].strip())
            for attr, key in INT_KEYS.items():
                if getattr(args, attr, None) is None and env.get(key, "").strip():
                    setattr(args, attr, int(env[key]))
            for attr, key in BOOL_KEYS.items():
                if not getattr(args, attr, False) and key in env:
                    setattr(args, attr, as_bool(env[key]))
        except (ValueError, EnvFileError) as exc:
            raise ConfigError(f"Invalid value in configuration: {exc}") from exc
        for attr, key in SECRET_KEYS.items():
            if not getattr(args, attr, None) and env.get(key, "").strip():
                setattr(args, attr, key)
    else:
        profile = (args.profile or "baseline") if command == "scan" else {"api-scan": "api", "ui-scan": "ui"}[command]

    if _unset(getattr(args, "report_format", None)):
        args.report_format = "html" if command == "run" else "text"
    if command == "run" and _unset(args.output):
        args.output = f"reports/securerelease-report.{FORMAT_EXTENSIONS.get(args.report_format, 'txt')}"
    for attr, default in (("ui_engine", "auto"), ("max_pages", 25), ("max_requests", 300), ("fail_on", "critical,high")):
        if getattr(args, attr, None) is None:
            setattr(args, attr, default)
    return profile, notes + _summary(args, profile, env)


def _profile_for(args: Namespace, command: str, env: MutableMapping[str, str]) -> str:
    if command in {"api-scan", "ui-scan"}:
        return "api" if command == "api-scan" else "ui"
    chosen = getattr(args, "profile", None) or (env.get("SECURERELEASE_PROFILE", "").strip().lower() if command == "run" else "")
    if chosen:
        if chosen not in PROFILES:
            raise ConfigError(f"Profile must be one of: {', '.join(PROFILES)}.")
        return chosen
    if command == "scan":
        return "baseline"
    present = {
        "ui": bool(args.url or env.get(TEXT_KEYS["url"], "").strip()),
        "api": bool(args.api_url or env.get(TEXT_KEYS["api_url"], "").strip()),
        "repository": bool(args.source or env.get(TEXT_KEYS["source"], "").strip()),
    }
    configured = [name for name, flag in present.items() if flag]
    if not configured:
        raise ConfigError(
            "No target is configured. Set SECURERELEASE_UI_URL, SECURERELEASE_API_URL or SECURERELEASE_SOURCE in .env "
            "(copy .env.example), run 'securerelease init', or pass --url / --api-url / --source."
        )
    return configured[0] if len(configured) == 1 else "full"


def _summary(args: Namespace, profile: str, env: MutableMapping[str, str]) -> list[str]:
    def secret(attr: str) -> str:
        name = getattr(args, attr, None)
        return "set" if name and env.get(name, "").strip() else "not set"

    lines = [f"Profile     : {profile}"]
    for label, attr in (("UI URL", "url"), ("API URL", "api_url"), ("OpenAPI", "openapi_spec"), ("Repository", "source")):
        if getattr(args, attr, None):
            lines.append(f"{label:<12}: {getattr(args, attr)}")
    if args.api_token_env or args.api_token_b_env:
        lines.append(f"API tokens  : user A {secret('api_token_env')}, user B {secret('api_token_b_env')}")
    if args.ui_user_env or args.ui_pass_env or args.ui_auth_header_env or args.ui_storage_state:
        lines.append("UI login    : configured")
    lines.append(f"Active tests: {'ON (--authorized)' if args.authorized else 'off (passive scan)'}")
    lines.append(f"Report      : {args.report_format}" + (f" -> {args.output}" if args.output else " -> terminal"))
    return lines
