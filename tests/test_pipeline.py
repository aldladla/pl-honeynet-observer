from pathlib import Path

from sqlalchemy.orm import sessionmaker

from honeynet.database import Base, build_engine
from honeynet.models import Event
from honeynet.reporting import render_session_report
from honeynet.repository import EventRepository

FIXTURE = Path(__file__).parents[1] / "fixtures" / "session_basic.jsonl"


def test_fixture_to_database_to_report(tmp_path: Path) -> None:
    engine = build_engine(f"sqlite:///{tmp_path / 'test.db'}")
    Base.metadata.create_all(engine)
    local_session = sessionmaker(bind=engine, expire_on_commit=False)
    events = [Event.model_validate_json(line) for line in FIXTURE.read_text().splitlines()]

    with local_session() as session:
        repository = EventRepository(session)
        assert repository.add_many(events) == (7, 0)
        assert repository.add_many(events) == (0, 7)
        stored = repository.session_events("session-basic-001")

    report = render_session_report(stored, "test-secret")
    assert "# Raport sesji session-basic-001" in report
    assert "source-" in report
    assert "192.0.2.123" not in report
    assert "test-user" not in report
    assert "2026-08-19T10:00:00+00:00" in report
    assert "Pojedyncza sesja nie dowodzi ukierunkowania" in report


def test_repository_redacts_secrets_from_generic_imports(tmp_path: Path) -> None:
    engine = build_engine(f"sqlite:///{tmp_path / 'privacy.db'}")
    Base.metadata.create_all(engine)
    local_session = sessionmaker(bind=engine, expire_on_commit=False)
    template = Event.model_validate_json(FIXTURE.read_text().splitlines()[3])
    event = template.model_copy(
        update={
            "event_id": "evt-generic-secret",
            "session_id": "session-generic-secret",
            "data": {"command": "curl --token inline-secret https://payload.invalid"},
            "source_event": {
                "password": "stored-secret",
                "headers": {"Authorization": "Bearer source-secret"},
            },
        }
    )

    with local_session() as session:
        repository = EventRepository(session)
        assert repository.add(event) is True
        stored = repository.session_events("session-generic-secret")[0]

    combined = f"{stored.data!r} {stored.source_event!r}"
    assert "inline-secret" not in combined
    assert "stored-secret" not in combined
    assert "source-secret" not in combined
    assert "[REDACTED]" in combined
