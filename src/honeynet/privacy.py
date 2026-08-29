"""Privacy guards applied before untrusted telemetry is persisted.

The sanitizer deliberately favours losing a secret over keeping a perfect copy of
an attacker-controlled record. It does not attempt to classify arbitrary personal
data; that remains a separate retention and access-control concern.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

REDACTED = "[REDACTED]"

_SENSITIVE_FIELDS = {
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "key",
    "passphrase",
    "passwd",
    "password",
    "private_key",
    "proxy_authorization",
    "pwd",
    "refresh_token",
    "secret",
    "set_cookie",
    "token",
    "access_token",
}

_FIELD_SEPARATOR = re.compile(r"[^a-z0-9]+")
_URL_PASSWORD = re.compile(
    r"(?P<prefix>\b[a-z][a-z0-9+.-]*://[^\s/:@]+:)(?P<secret>[^\s/@]+)@",
    re.IGNORECASE,
)
_BEARER_TOKEN = re.compile(
    r"(?P<scheme>\b(?:bearer|basic)\s+)[a-z0-9._~+/=-]+",
    re.IGNORECASE,
)
_CLI_SECRET = re.compile(
    r"(?P<prefix>--(?:password|passwd|passphrase|token|access-token|api-key|secret)\s+)"
    r"(?P<secret>\"[^\"]*\"|'[^']*'|[^\s;&|]+)",
    re.IGNORECASE,
)
_ASSIGNED_SECRET = re.compile(
    r"(?P<name>\b(?:password|passwd|pwd|passphrase|token|access[_-]?token|"
    r"refresh[_-]?token|api[_-]?key|secret|authorization)\b)"
    r"(?P<separator>\s*(?:=|:)\s*)"
    r"(?P<secret>\"[^\"]*\"|'[^']*'|[^\s;&|]+)",
    re.IGNORECASE,
)


def _normalized_field_name(value: object) -> str:
    return _FIELD_SEPARATOR.sub("_", str(value).strip().lower()).strip("_")


def is_sensitive_field(name: object) -> bool:
    """Return whether a JSON field name conventionally contains a secret."""

    return _normalized_field_name(name) in _SENSITIVE_FIELDS


def redact_text(value: str) -> str:
    """Mask common inline credential forms without executing or opening anything."""

    value = _URL_PASSWORD.sub(lambda match: f"{match.group('prefix')}{REDACTED}@", value)
    value = _BEARER_TOKEN.sub(lambda match: f"{match.group('scheme')}{REDACTED}", value)
    value = _CLI_SECRET.sub(lambda match: f"{match.group('prefix')}{REDACTED}", value)
    return _ASSIGNED_SECRET.sub(
        lambda match: f"{match.group('name')}{match.group('separator')}{REDACTED}",
        value,
    )


def sanitize_json(value: Any) -> Any:
    """Recursively return a JSON-compatible copy with likely secrets removed."""

    if isinstance(value, Mapping):
        return {
            str(key): REDACTED if is_sensitive_field(key) else sanitize_json(item)
            for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [sanitize_json(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
