"""Privacy-first retention for the current single-table pilot schema."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from honeynet.repository import EventRepository

PILOT_MAX_RETENTION_DAYS = 30


@dataclass(frozen=True, slots=True)
class RetentionResult:
    cutoff: datetime
    eligible: int
    deleted: int
    dry_run: bool


def apply_retention(
    repository: EventRepository,
    *,
    days: int = PILOT_MAX_RETENTION_DAYS,
    execute: bool = False,
    now: datetime | None = None,
) -> RetentionResult:
    """Preview or remove events older than the pilot retention window.

    The current schema keeps raw and normalized fields in one row. Until those
    layers are separated, deleting the entire expired row is safer than retaining
    raw identifiers for the longer analytical window.
    """

    if not 1 <= days <= PILOT_MAX_RETENTION_DAYS:
        raise ValueError(f"days must be between 1 and {PILOT_MAX_RETENTION_DAYS}")

    reference = now or datetime.now(UTC)
    if reference.tzinfo is None or reference.utcoffset() is None:
        raise ValueError("now must include a timezone")
    cutoff = reference.astimezone(UTC) - timedelta(days=days)
    eligible = repository.count_before(cutoff)
    deleted = repository.delete_before(cutoff) if execute and eligible else 0
    return RetentionResult(
        cutoff=cutoff,
        eligible=eligible,
        deleted=deleted,
        dry_run=not execute,
    )
