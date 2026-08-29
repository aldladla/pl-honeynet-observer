from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from honeynet.collector import CowrieFileCollector, CursorState
from honeynet.database import Base, StoredEvent, build_engine
from honeynet.health import check_collector_state

FIXTURE = Path(__file__).parents[1] / "fixtures" / "cowrie_live_demo.jsonl"


def collector_for(tmp_path: Path):
    engine = build_engine(f"sqlite:///{tmp_path / 'collector.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    log_path = tmp_path / "cowrie.json"
    state_path = tmp_path / "cursor.json"
    return CowrieFileCollector(log_path, state_path, sessions), log_path, state_path, sessions


def test_collector_waits_for_missing_file(tmp_path: Path) -> None:
    collector, _, state_path, _ = collector_for(tmp_path)

    result = collector.poll_once()

    assert result.waiting_for_file is True
    assert result.lines_read == 0
    assert check_collector_state(state_path, max_age_seconds=30).healthy is True


def test_collector_reads_complete_lines_and_resumes_from_cursor(tmp_path: Path) -> None:
    collector, log_path, state_path, sessions = collector_for(tmp_path)
    lines = FIXTURE.read_bytes().splitlines()
    split_at = len(lines[1]) // 2
    log_path.write_bytes(lines[0] + b"\n" + lines[1][:split_at])

    first = collector.poll_once()

    assert first.lines_read == 1
    assert first.events_inserted == 1
    assert CursorState.load(state_path).offset == len(lines[0]) + 1

    with log_path.open("ab") as stream:
        stream.write(lines[1][split_at:] + b"\n")

    second = collector.poll_once()
    third = collector.poll_once()

    assert second.lines_read == 1
    assert second.events_inserted == 1
    assert third.lines_read == 0
    with sessions() as session:
        assert len(list(session.scalars(select(StoredEvent)))) == 2


def test_collector_advances_past_invalid_and_ignored_records(tmp_path: Path) -> None:
    collector, log_path, state_path, sessions = collector_for(tmp_path)
    valid = FIXTURE.read_text(encoding="utf-8").splitlines()[3]
    unknown = (
        '{"eventid":"cowrie.client.version","sensor":"pl-live-lab-01",'
        '"timestamp":"2026-08-20T08:15:06Z","session":"live-demo-20260820",'
        '"src_ip":"203.0.113.77"}'
    )
    log_path.write_text(f"not-json\n{unknown}\n{valid}\n", encoding="utf-8")

    result = collector.poll_once()

    assert result.lines_read == 3
    assert result.errors == 1
    assert result.ignored == 1
    assert result.events_inserted == 1
    assert CursorState.load(state_path).offset == log_path.stat().st_size
    with sessions() as session:
        stored = list(session.scalars(select(StoredEvent)))
    assert stored[0].event_type == "command_input"


def test_collector_restarts_at_zero_after_truncation(tmp_path: Path) -> None:
    collector, log_path, _, sessions = collector_for(tmp_path)
    lines = FIXTURE.read_text(encoding="utf-8").splitlines()
    log_path.write_text("\n".join(lines[:4]) + "\n", encoding="utf-8")
    assert collector.poll_once().events_inserted == 4

    log_path.write_text(lines[-1] + "\n", encoding="utf-8")
    after_truncation = collector.poll_once()

    assert after_truncation.events_inserted == 1
    with sessions() as session:
        assert len(list(session.scalars(select(StoredEvent)))) == 5


def test_collector_health_distinguishes_stale_and_invalid_heartbeat(tmp_path: Path) -> None:
    state_path = tmp_path / "cursor.json"
    now = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
    CursorState(last_poll_at=(now - timedelta(seconds=31)).isoformat()).save(state_path)

    stale = check_collector_state(state_path, max_age_seconds=30, now=now)

    assert stale.healthy is False
    assert stale.status == "heartbeat_stale"
    assert stale.age_seconds == 31

    CursorState(last_poll_at="not-a-timestamp").save(state_path)
    invalid = check_collector_state(state_path, max_age_seconds=30, now=now)
    assert invalid.healthy is False
    assert invalid.status == "heartbeat_invalid"
