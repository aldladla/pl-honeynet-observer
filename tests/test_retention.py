from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.orm import sessionmaker

from honeynet.database import Base, build_engine
from honeynet.models import Event
from honeynet.repository import EventRepository
from honeynet.retention import apply_retention

FIXTURE = Path(__file__).parents[1] / "fixtures" / "session_basic.jsonl"


def _repository(tmp_path: Path) -> tuple[EventRepository, object]:
    engine = build_engine(f"sqlite:///{tmp_path / 'retention.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    return EventRepository(session), session


def test_retention_is_dry_run_by_default_and_deletes_only_expired_rows(
    tmp_path: Path,
) -> None:
    repository, session = _repository(tmp_path)
    now = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
    template = Event.model_validate_json(FIXTURE.read_text().splitlines()[0])
    old = template.model_copy(
        update={"event_id": "evt-old", "timestamp": now - timedelta(days=31)}
    )
    boundary = template.model_copy(
        update={"event_id": "evt-boundary", "timestamp": now - timedelta(days=30)}
    )
    recent = template.model_copy(
        update={"event_id": "evt-recent", "timestamp": now - timedelta(days=1)}
    )
    assert repository.add_many([old, boundary, recent]) == (3, 0)

    preview = apply_retention(repository, now=now)

    assert preview.eligible == 1
    assert preview.deleted == 0
    assert preview.dry_run is True
    assert len(repository.all_events()) == 3

    executed = apply_retention(repository, now=now, execute=True)

    assert executed.eligible == 1
    assert executed.deleted == 1
    assert {event.event_id for event in repository.all_events()} == {
        "evt-boundary",
        "evt-recent",
    }
    session.close()


@pytest.mark.parametrize("days", [0, 31])
def test_retention_rejects_windows_outside_pilot_policy(tmp_path: Path, days: int) -> None:
    repository, session = _repository(tmp_path)

    with pytest.raises(ValueError, match="between 1 and 30"):
        apply_retention(repository, days=days)

    session.close()


def test_retention_requires_timezone_aware_reference(tmp_path: Path) -> None:
    repository, session = _repository(tmp_path)
    naive_reference = datetime(2026, 8, 21, tzinfo=UTC).replace(tzinfo=None)

    with pytest.raises(ValueError, match="timezone"):
        apply_retention(repository, now=naive_reference)

    session.close()


def test_all_events_limit_keeps_the_newest_rows_in_chronological_order(
    tmp_path: Path,
) -> None:
    repository, session = _repository(tmp_path)
    template = Event.model_validate_json(FIXTURE.read_text().splitlines()[0])
    base = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
    events = [
        template.model_copy(
            update={"event_id": f"evt-{index}", "timestamp": base + timedelta(minutes=index)}
        )
        for index in range(4)
    ]
    assert repository.add_many(events) == (4, 0)

    recent = repository.all_events(limit=2)

    assert [event.event_id for event in recent] == ["evt-2", "evt-3"]
    session.close()
