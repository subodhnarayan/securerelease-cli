"""Minimal .env support so a scan can be configured from a file instead of command-line flags.

Precedence (highest first): command-line flag, real environment variable, value from the .env file.
Secrets stay in the environment; they are never copied into argparse values or reports.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Mapping

KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
TRUE_VALUES = {"1", "true", "yes", "on", "y"}
FALSE_VALUES = {"", "0", "false", "no", "off", "n"}


class EnvFileError(ValueError):
    """The .env file is missing or malformed."""


def parse_env(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not KEY_PATTERN.match(key):
            raise EnvFileError(f"Line {number}: expected KEY=value.")
        value = value.strip()
        if value[:1] in {'"', "'"}:
            end = value.find(value[0], 1)
            if end == -1:
                raise EnvFileError(f"Line {number}: unterminated quote for {key}.")
            value = value[1:end]
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
        values[key] = value
    return values


def load_env_file(path: str | Path) -> dict[str, str]:
    target = Path(path).expanduser()
    if not target.is_file():
        raise EnvFileError(f"Config file not found: {target}")
    try:
        return parse_env(target.read_text(encoding="utf-8"))
    except OSError as exc:
        raise EnvFileError(f"Could not read {target}: {exc.__class__.__name__}.") from exc


def apply_env(values: Mapping[str, str], environ: dict[str, str] | None = None) -> list[str]:
    """Add file values to the environment without overriding variables that are already set."""
    target = os.environ if environ is None else environ
    applied = []
    for key, value in values.items():
        if key not in target:
            target[key] = value
            applied.append(key)
    return applied


def as_bool(value: str | None) -> bool:
    text = (value or "").strip().lower()
    if text in TRUE_VALUES:
        return True
    if text in FALSE_VALUES:
        return False
    raise EnvFileError(f"Cannot read '{value}' as yes/no. Use true or false.")
