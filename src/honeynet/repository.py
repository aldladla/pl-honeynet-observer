from collections.abc import Iterable
from datetime import datetime

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from honeynet.database import StoredEvent
from honeynet.models import Event
from honeynet.privacy import sanitize_json


class EventRepository:
    def __init__(self, session: Session):
        self.session = session

    def add(self, event: Event) -> bool:
        record = StoredEvent(
            event_id=event.event_id,
            event_type=event.event_type.value,
            timestamp=event.timestamp,
            sensor_id=event.sensor_id,
            session_id=event.session_id,
            source_ip=str(event.source_ip),
            source_port=event.source_port,
            destination_port=event.destination_port,
            # Treat the repository as the final privacy boundary too. This also
            # protects imports that did not pass through the Cowrie adapter.
            data=sanitize_json(event.data),
            source_event=sanitize_json(event.source_event),
        )
        self.session.add(record)
        try:
            self.session.commit()
        except IntegrityError:
            self.session.rollback()
            return False
        return True

    def add_many(self, events: Iterable[Event]) -> tuple[int, int]:
        inserted = duplicates = 0
        for event in events:
            if self.add(event):
                inserted += 1
            else:
                duplicates += 1
        return inserted, duplicates

    def list_events(self, *, limit: int = 100) -> list[StoredEvent]:
        statement = select(StoredEvent).order_by(StoredEvent.timestamp.desc()).limit(limit)
        return list(self.session.scalars(statement))

    def all_events(self, *, limit: int = 50_000) -> list[StoredEvent]:
        statement = select(StoredEvent).order_by(StoredEvent.timestamp.desc()).limit(limit)
        newest_first = list(self.session.scalars(statement))
        return list(reversed(newest_first))

    def count_events(self) -> int:
        statement = select(func.count()).select_from(StoredEvent)
        return int(self.session.scalar(statement) or 0)

    def artifact_events(self, *, limit: int = 10_000) -> list[StoredEvent]:
        statement = (
            select(StoredEvent)
            .where(StoredEvent.event_type == "artifact_captured")
            .order_by(StoredEvent.timestamp.asc())
            .limit(limit)
        )
        return list(self.session.scalars(statement))

    def download_request_events(self, *, limit: int = 10_000) -> list[StoredEvent]:
        statement = (
            select(StoredEvent)
            .where(StoredEvent.event_type == "file_download_requested")
            .order_by(StoredEvent.timestamp.asc())
            .limit(limit)
        )
        return list(self.session.scalars(statement))

    def session_events(self, session_id: str) -> list[StoredEvent]:
        statement = (
            select(StoredEvent)
            .where(StoredEvent.session_id == session_id)
            .order_by(StoredEvent.timestamp.asc())
        )
        return list(self.session.scalars(statement))

    def count_before(self, cutoff: datetime) -> int:
        statement = select(func.count()).select_from(StoredEvent).where(
            StoredEvent.timestamp < cutoff
        )
        return int(self.session.scalar(statement) or 0)

    def delete_before(self, cutoff: datetime) -> int:
        """Delete expired events in one transaction and return the affected count."""

        result = self.session.execute(delete(StoredEvent).where(StoredEvent.timestamp < cutoff))
        self.session.commit()
        return int(result.rowcount or 0)
