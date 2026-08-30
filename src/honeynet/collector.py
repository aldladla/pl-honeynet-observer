"""Incremental Cowrie JSONL collector with a durable byte cursor.

The collector reads metadata only. It never opens artifacts referenced by Cowrie.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.orm import Session

from honeynet.cowrie import normalize_cowrie
from honeynet.repository import EventRepository

SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class CollectorResult:
    lines_read: int = 0
    events_inserted: int = 0
    duplicates: int = 0
    ignored: int = 0
    errors: int = 0
    waiting_for_file: bool = False


@dataclass
class CursorState:
    file_identity: str = ""
    offset: int = 0
    updated_at: str = ""
    last_poll_at: str = ""

    @classmethod
    def load(cls, path: Path) -> CursorState:
        if not path.exists():
            return cls()
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            return cls(
                file_identity=str(payload.get("file_identity", "")),
                offset=max(0, int(payload.get("offset", 0))),
                updated_at=str(payload.get("updated_at", "")),
                last_poll_at=str(payload.get("last_poll_at", "")),
            )
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            return cls()

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(f"{path.suffix}.tmp")
        temporary.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        temporary.replace(path)


class CowrieFileCollector:
    """Read complete lines appended since the last successful poll."""

    def __init__(
        self,
        log_path: Path,
        state_path: Path,
        session_factory: Callable[[], Session],
        artifact_root: Path | None = None,
    ) -> None:
        self.log_path = log_path
        self.state_path = state_path
        self.session_factory = session_factory
        self.artifact_root = artifact_root

    def _enrich_artifact_size(self, record: dict[str, object]) -> None:
        """Add a size using filesystem metadata only; never open sample content."""

        if record.get("eventid") not in {
            "cowrie.session.file_download",
            "cowrie.session.file_upload",
        }:
            return
        if isinstance(record.get("size"), int) or self.artifact_root is None:
            return
        sha256 = record.get("shasum")
        if not isinstance(sha256, str) or not SHA256_PATTERN.fullmatch(sha256):
            return
        candidate = self.artifact_root / sha256.lower()
        try:
            if candidate.is_file():
                record["size"] = candidate.stat().st_size
        except OSError:
            return

    @staticmethod
    def _identity(stat_result) -> str:
        return f"{stat_result.st_dev}:{stat_result.st_ino}"

    def poll_once(self) -> CollectorResult:
        polled_at = datetime.now(UTC).isoformat()
        cursor = CursorState.load(self.state_path)
        if not self.log_path.exists():
            cursor.last_poll_at = polled_at
            cursor.save(self.state_path)
            return CollectorResult(waiting_for_file=True)

        stat_result = self.log_path.stat()
        identity = self._identity(stat_result)
        if cursor.file_identity != identity or stat_result.st_size < cursor.offset:
            cursor = CursorState(file_identity=identity, last_poll_at=polled_at)

        with self.log_path.open("rb") as stream:
            stream.seek(cursor.offset)
            available = stream.read()

        last_newline = available.rfind(b"\n")
        if last_newline < 0:
            cursor.last_poll_at = polled_at
            cursor.save(self.state_path)
            return CollectorResult()

        complete = available[: last_newline + 1]
        next_offset = cursor.offset + len(complete)
        lines = complete.splitlines()
        inserted = duplicates = ignored = errors = 0

        with self.session_factory() as session:
            repository = EventRepository(session)
            for raw_line in lines:
                if not raw_line.strip():
                    ignored += 1
                    continue
                try:
                    line = raw_line.decode("utf-8")
                    record = json.loads(line)
                    if not isinstance(record, dict):
                        raise TypeError("rekord nie jest obiektem JSON")
                    self._enrich_artifact_size(record)
                    events = normalize_cowrie(record)
                except (UnicodeDecodeError, TypeError, ValueError, json.JSONDecodeError):
                    errors += 1
                    continue
                if not events:
                    ignored += 1
                    continue
                added, repeated = repository.add_many(events)
                inserted += added
                duplicates += repeated

        CursorState(
            file_identity=identity,
            offset=next_offset,
            updated_at=polled_at,
            last_poll_at=polled_at,
        ).save(self.state_path)
        return CollectorResult(
            lines_read=len(lines),
            events_inserted=inserted,
            duplicates=duplicates,
            ignored=ignored,
            errors=errors,
        )
