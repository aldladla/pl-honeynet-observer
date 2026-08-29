from datetime import UTC, datetime, timedelta

from honeynet.acquisition import acquisition_candidate_manifest, acquisition_candidate_queue
from honeynet.database import StoredEvent


def download_event(
    *,
    event_id: str,
    session_id: str,
    source_ip: str,
    timestamp: datetime,
    url: str = "https://payload.example.invalid/bin/sample",
    outcome: str = "failed",
) -> StoredEvent:
    return StoredEvent(
        event_id=event_id,
        event_type="file_download_requested",
        timestamp=timestamp,
        sensor_id="pl-test-sensor-01",
        session_id=session_id,
        source_ip=source_ip,
        source_port=41000,
        destination_port=2222,
        data={
            "url": url,
            "tool": "wget",
            "outcome": outcome,
            "destination_filename": "/tmp/sample",
        },
        source_event={
            "password": "must-not-leak",
            "url": url,
        },
    )


def test_candidate_queue_deduplicates_locations_without_exposing_them() -> None:
    started = datetime(2026, 8, 28, 10, 0, tzinfo=UTC)
    url = "https://payload.example.invalid/bin/sample"
    events = [
        download_event(
            event_id="download-1",
            session_id="session-1",
            source_ip="192.0.2.10",
            timestamp=started,
            url=url,
        ),
        download_event(
            event_id="download-2",
            session_id="session-2",
            source_ip="198.51.100.20",
            timestamp=started + timedelta(minutes=2),
            url=url,
        ),
    ]

    payload = acquisition_candidate_queue(events, "test-pseudonym-key")

    assert payload["status"] == "passive_intake_only"
    assert payload["fetcher_status"] == "disabled"
    assert payload["candidate_count"] == 1
    assert payload["observation_count"] == 2
    candidate = payload["candidates"][0]
    assert candidate["candidate_id"].startswith("candidate-")
    assert candidate["observation_count"] == 2
    assert candidate["session_count"] == 2
    assert candidate["schemes"] == ["https"]
    assert candidate["intake_active_24_7"] is True
    assert candidate["content_retrieved"] is False
    assert candidate["automated_fetch_allowed"] is False
    assert url not in str(payload)
    assert "payload.example.invalid" not in str(payload)


def test_candidate_manifest_is_allowlisted_and_metadata_only() -> None:
    event = download_event(
        event_id="download-1",
        session_id="session-1",
        source_ip="192.0.2.10",
        timestamp=datetime(2026, 8, 28, 10, 0, tzinfo=UTC),
    )
    queue = acquisition_candidate_queue([event], "test-pseudonym-key")
    candidate_id = queue["candidates"][0]["candidate_id"]

    manifest = acquisition_candidate_manifest(
        [event],
        candidate_id,
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
    assert manifest["handling"]["fetcher_provisioned"] is False
    assert manifest["handling"]["operator_approval_required"] is True
    assert manifest["handling"]["network_location_included"] is False
    assert manifest["observations"][0]["source"].startswith("source-")
    serialized = str(manifest)
    assert "192.0.2.10" not in serialized
    assert "payload.example.invalid" not in serialized
    assert "must-not-leak" not in serialized
    assert "source_event" not in serialized
    assert "provider" not in serialized


def test_candidate_identifier_is_keyed_and_unknown_identifier_returns_none() -> None:
    event = download_event(
        event_id="download-1",
        session_id="session-1",
        source_ip="192.0.2.10",
        timestamp=datetime(2026, 8, 28, 10, 0, tzinfo=UTC),
    )

    first = acquisition_candidate_queue([event], "first-key")["candidates"][0]
    second = acquisition_candidate_queue([event], "second-key")["candidates"][0]

    assert first["candidate_id"] != second["candidate_id"]
    assert acquisition_candidate_manifest([event], "candidate-missing", "first-key") is None
