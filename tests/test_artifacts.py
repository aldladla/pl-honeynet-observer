from datetime import UTC, datetime, timedelta

from honeynet.artifacts import artifact_manifest, artifact_queue
from honeynet.database import StoredEvent


def artifact_event(
    *,
    event_id: str,
    session_id: str,
    source_ip: str,
    timestamp: datetime,
    filename: str,
) -> StoredEvent:
    return StoredEvent(
        event_id=event_id,
        event_type="artifact_captured",
        timestamp=timestamp,
        sensor_id="pl-test-sensor-01",
        session_id=session_id,
        source_ip=source_ip,
        source_port=41000,
        destination_port=2222,
        data={
            "sha256": "a" * 64,
            "size_bytes": 42,
            "media_type": "application/octet-stream",
            "filename": filename,
            "origin": "direct_upload",
            "role": "script",
        },
        source_event={
            "password": "must-not-leak",
            "url": "https://payload.invalid/sample",
        },
    )


def test_artifact_queue_deduplicates_by_full_sha256() -> None:
    started = datetime(2026, 8, 26, 10, 0, tzinfo=UTC)
    events = [
        artifact_event(
            event_id="artifact-observation-1",
            session_id="session-1",
            source_ip="192.0.2.10",
            timestamp=started,
            filename="first.sh",
        ),
        artifact_event(
            event_id="artifact-observation-2",
            session_id="session-2",
            source_ip="198.51.100.20",
            timestamp=started + timedelta(minutes=2),
            filename="second.sh",
        ),
    ]

    payload = artifact_queue(events)

    assert payload["status"] == "metadata_only"
    assert payload["artifact_count"] == 1
    assert payload["observation_count"] == 2
    artifact = payload["artifacts"][0]
    assert artifact["artifact_id"] == f"artifact-{'a' * 64}"
    assert artifact["filenames"] == ["first.sh", "second.sh"]
    assert artifact["session_count"] == 2
    assert artifact["content_exposed_by_api"] is False
    assert artifact["execution_allowed"] is False


def test_artifact_manifest_is_allowlisted_and_contains_no_content_location() -> None:
    event = artifact_event(
        event_id="artifact-observation-1",
        session_id="session-1",
        source_ip="192.0.2.10",
        timestamp=datetime(2026, 8, 26, 10, 0, tzinfo=UTC),
        filename="sample.sh",
    )

    manifest = artifact_manifest(
        [event],
        f"artifact-{'a' * 64}",
        "test-pseudonym-key",
        lambda _ip: {
            "country_code": "PL",
            "country_name": "Polska",
            "asn": 64500,
            "organization": "Example Network",
            "provider": "local_mmdb",
            "scope": "network_infrastructure",
        },
    )

    assert manifest is not None
    assert manifest["handling"]["content_included"] is False
    assert manifest["handling"]["network_location_included"] is False
    assert manifest["observations"][0]["source"].startswith("source-")
    serialized = str(manifest)
    assert "192.0.2.10" not in serialized
    assert "must-not-leak" not in serialized
    assert "payload.invalid" not in serialized
    assert "source_event" not in serialized
    assert "provider" not in serialized


def test_artifact_manifest_returns_none_for_unknown_identifier() -> None:
    assert artifact_manifest([], f"artifact-{'b' * 64}", "test-key") is None


def test_empty_artifact_has_explicit_queue_state_and_known_zero_size() -> None:
    event = artifact_event(
        event_id="empty-artifact",
        session_id="empty-session",
        source_ip="192.0.2.10",
        timestamp=datetime(2026, 8, 29, 10, 0, tzinfo=UTC),
        filename="sshd",
    )
    event.data.update(
        {
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "size_bytes": 0,
            "capture_status": "empty_upload",
        }
    )

    artifact = artifact_queue([event])["artifacts"][0]

    assert artifact["sizes_bytes"] == [0]
    assert artifact["capture_statuses"] == ["empty_upload"]
    assert artifact["workflow_state"] == "empty_upload"


def test_queue_backfills_legacy_size_from_exact_sha_named_quarantine_file(tmp_path) -> None:
    event = artifact_event(
        event_id="legacy-artifact",
        session_id="legacy-session",
        source_ip="192.0.2.10",
        timestamp=datetime(2026, 8, 29, 10, 0, tzinfo=UTC),
        filename="legacy.bin",
    )
    event.data.pop("size_bytes")
    quarantine = tmp_path / "downloads"
    quarantine.mkdir()
    (quarantine / ("a" * 64)).write_bytes(b"legacy-size")

    artifact = artifact_queue([event], quarantine)["artifacts"][0]

    assert artifact["sizes_bytes"] == [11]
