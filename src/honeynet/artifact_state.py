"""Shared metadata-only classification for captured artifact records."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
INCOMPLETE_STATUSES = {"empty_upload", "incomplete_transfer"}


def artifact_capture_status(data: Mapping[str, Any]) -> str:
    explicit = data.get("capture_status")
    if explicit in {"complete", "empty_upload", "incomplete_transfer", "unknown"}:
        return str(explicit)
    if str(data.get("sha256", "")).lower() == EMPTY_SHA256:
        return "empty_upload"
    size = data.get("size_bytes")
    if isinstance(size, int) and not isinstance(size, bool):
        return "incomplete_transfer" if size == 0 else "complete"
    return "unknown"


def is_meaningful_artifact(data: Mapping[str, Any]) -> bool:
    return artifact_capture_status(data) not in INCOMPLETE_STATUSES
