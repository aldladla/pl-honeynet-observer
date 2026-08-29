import json
from datetime import UTC
from pathlib import Path

import pytest
from pydantic import ValidationError

from honeynet.models import Event, EventType, parse_event

FIXTURE_PATH = Path(__file__).parents[1] / "fixtures" / "session_basic.jsonl"


def load_fixture() -> list[dict[str, object]]:
    return [json.loads(line) for line in FIXTURE_PATH.read_text(encoding="utf-8").splitlines()]


def test_fixture_contains_valid_complete_session() -> None:
    events = [Event.model_validate(item) for item in load_fixture()]

    assert len(events) == 7
    assert events[0].event_type is EventType.CONNECTION_OPENED
    assert events[-1].event_type is EventType.CONNECTION_CLOSED
    assert {event.session_id for event in events} == {"session-basic-001"}
    assert len({event.event_id for event in events}) == len(events)
    assert [event.timestamp for event in events] == sorted(event.timestamp for event in events)
    assert all(event.timestamp.tzinfo == UTC for event in events)


def test_event_round_trips_as_json_safe_record() -> None:
    event = Event.model_validate(load_fixture()[0])

    dumped = event.model_dump(mode="json")

    assert dumped["event_type"] == "connection_opened"
    assert dumped["timestamp"] == "2026-08-19T10:00:00Z"
    assert dumped["source_ip"] == "192.0.2.123"
    assert Event.model_validate(dumped) == event


def test_payload_is_validated_for_event_type() -> None:
    event = parse_event(load_fixture()[4])

    assert event.data["url"] == "https://downloads.example.invalid/sample-test.bin"
    assert event.data["tool"] == "curl"


def test_timestamp_with_offset_is_normalized_to_utc() -> None:
    raw = load_fixture()[0]
    raw["timestamp"] = "2026-08-19T12:00:00+02:00"

    event = Event.model_validate(raw)

    assert event.timestamp.isoformat() == "2026-08-19T10:00:00+00:00"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timestamp", "2026-08-19T10:00:00"),
        ("source_ip", "not-an-ip"),
        ("source_port", 0),
        ("destination_port", 65_536),
        ("sensor_id", "contains spaces"),
    ],
)
def test_invalid_common_fields_are_rejected(field: str, value: object) -> None:
    raw = load_fixture()[0]
    raw[field] = value

    with pytest.raises(ValidationError):
        Event.model_validate(raw)


def test_optional_network_fields_may_be_absent() -> None:
    raw = load_fixture()[0]
    raw.pop("source_port")
    raw.pop("destination_ip")
    raw.pop("destination_port")

    event = Event.model_validate(raw)

    assert event.source_port is None
    assert event.destination_ip is None
    assert event.destination_port is None


def test_unknown_event_type_is_rejected() -> None:
    raw = load_fixture()[0]
    raw["event_type"] = "unknown_event"

    with pytest.raises(ValidationError):
        Event.model_validate(raw)


def test_payload_shape_must_match_event_type() -> None:
    raw = load_fixture()[3]
    raw["data"] = {"username": "test-user", "success": True}

    with pytest.raises(ValidationError):
        Event.model_validate(raw)


def test_extra_fields_are_rejected() -> None:
    raw = load_fixture()[0]
    raw["unexpected"] = "value"

    with pytest.raises(ValidationError):
        Event.model_validate(raw)


def test_default_data_is_independent_per_event() -> None:
    raw = load_fixture()[2]
    raw.pop("data")
    first = Event.model_validate(raw)
    raw["event_id"] = "evt-basic-other"
    second = Event.model_validate(raw)

    first.data["local"] = True

    assert second.data == {}
