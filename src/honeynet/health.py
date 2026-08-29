"""Operational health checks that do not require privileged container access."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from honeynet.collector import CursorState


@dataclass(frozen=True, slots=True)
class CollectorHealth:
    healthy: bool
    status: str
    age_seconds: float | None


def check_collector_state(
    path: Path,
    *,
    max_age_seconds: float,
    now: datetime | None = None,
) -> CollectorHealth:
    if max_age_seconds <= 0:
        raise ValueError("max_age_seconds must be greater than zero")
    if not path.is_file():
        return CollectorHealth(False, "state_missing", None)

    state = CursorState.load(path)
    if not state.last_poll_at:
        return CollectorHealth(False, "heartbeat_missing", None)
    try:
        heartbeat = datetime.fromisoformat(state.last_poll_at)
    except ValueError:
        return CollectorHealth(False, "heartbeat_invalid", None)
    if heartbeat.tzinfo is None or heartbeat.utcoffset() is None:
        return CollectorHealth(False, "heartbeat_invalid", None)

    reference = now or datetime.now(UTC)
    if reference.tzinfo is None or reference.utcoffset() is None:
        raise ValueError("now must include a timezone")
    age = max(0.0, (reference.astimezone(UTC) - heartbeat.astimezone(UTC)).total_seconds())
    if age > max_age_seconds:
        return CollectorHealth(False, "heartbeat_stale", age)
    return CollectorHealth(True, "ok", age)
