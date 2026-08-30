from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from honeynet.api import app, database_session
from honeynet.cowrie import normalize_lines
from honeynet.dashboard import dashboard_session
from honeynet.database import Base, StoredEvent, build_engine
from honeynet.repository import EventRepository

FIXTURES = Path(__file__).parents[1] / "fixtures"


def test_dashboard_serves_sanitized_session_trace(tmp_path: Path) -> None:
    engine = build_engine(f"sqlite:///{tmp_path / 'dashboard.db'}")
    Base.metadata.create_all(engine)
    local_session = sessionmaker(bind=engine, expire_on_commit=False)

    with (FIXTURES / "cowrie_basic.jsonl").open(encoding="utf-8") as stream:
        normalized = list(normalize_lines(stream))
    with local_session() as session:
        EventRepository(session).add_many(normalized)

    def override_session() -> Generator[Session, None, None]:
        with local_session() as session:
            yield session

    app.dependency_overrides[database_session] = override_session
    try:
        with TestClient(app) as client:
            page = client.get("/")
            overview = client.get("/api/dashboard/overview")
            detail = client.get("/api/dashboard/sessions/cowrie-basic-001")
    finally:
        app.dependency_overrides.clear()

    assert page.status_code == 200
    assert "Zobacz zachowanie" in page.text
    assert "Detekcje" in page.text
    assert "Łańcuch ataku" in page.text
    assert "Artefakty do triage" in page.text
    assert overview.json()["session_count"] == 1
    assert overview.json()["event_count"] == 5
    assert overview.json()["analyzed_event_count"] == 5
    assert overview.json()["event_limit"] == 50_000
    assert overview.json()["truncated"] is False
    assert overview.json()["detection_count"] == 1
    payload = detail.json()
    assert payload["source"].startswith("source-")
    assert payload["risk"]["level"] == "high"
    assert payload["detection_count"] == 1
    assert payload["detections"][0]["category"] == "payload_delivery"
    assert [event["event_type"] for event in payload["timeline"]][-1] == "connection_closed"
    assert "source_event" not in detail.text
    assert "synthetic-only" not in detail.text


def test_dashboard_deep_link_is_not_limited_to_sessions_in_overview() -> None:
    script = (Path(__file__).parents[1] / "src" / "honeynet" / "static" / "dashboard.js").read_text(
        encoding="utf-8"
    )

    assert "hashSession ||" in script
    assert "selectSession(state.activeSessionId" in script


def test_dashboard_displays_operator_time_as_fixed_utc_plus_two() -> None:
    static_root = Path(__file__).parents[1] / "src" / "honeynet" / "static"
    script = (static_root / "dashboard.js").read_text(encoding="utf-8")
    page = (static_root / "index.html").read_text(encoding="utf-8")

    assert 'const displayTimeZone = "Etc/GMT-2"' in script
    assert 'const displayTimeZoneLabel = "UTC+2"' in script
    assert 'timeZone: "UTC"' not in script
    assert "Początek UTC+2" in page
    assert "UTC+2 / kolejność rosnąca" in page


def test_dashboard_exposes_metadata_only_artifact_manifest(tmp_path: Path) -> None:
    engine = build_engine(f"sqlite:///{tmp_path / 'artifact-dashboard.db'}")
    Base.metadata.create_all(engine)
    local_session = sessionmaker(bind=engine, expire_on_commit=False)
    with (FIXTURES / "cowrie_session_intelligence.jsonl").open(encoding="utf-8") as stream:
        normalized = list(normalize_lines(stream))
    with local_session() as session:
        EventRepository(session).add_many(normalized)

    def override_session() -> Generator[Session, None, None]:
        with local_session() as session:
            yield session

    app.dependency_overrides[database_session] = override_session
    try:
        with TestClient(app) as client:
            queue = client.get("/api/dashboard/artifacts")
            artifact_id = queue.json()["artifacts"][0]["artifact_id"]
            manifest = client.get(f"/api/dashboard/artifacts/{artifact_id}/manifest")
            missing = client.get(f"/api/dashboard/artifacts/artifact-{'f' * 64}/manifest")
    finally:
        app.dependency_overrides.clear()

    assert queue.status_code == 200
    assert queue.json()["artifact_count"] == 1
    assert manifest.status_code == 200
    assert manifest.json()["handling"]["content_included"] is False
    assert manifest.json()["artifact"]["workflow_state"] == "metadata_only"
    assert "192.0.2.55" not in manifest.text
    assert "scp://" not in manifest.text
    assert missing.status_code == 404


def test_dashboard_exposes_passive_acquisition_candidate_manifest(tmp_path: Path) -> None:
    engine = build_engine(f"sqlite:///{tmp_path / 'candidate-dashboard.db'}")
    Base.metadata.create_all(engine)
    local_session = sessionmaker(bind=engine, expire_on_commit=False)
    with (FIXTURES / "cowrie_session_intelligence.jsonl").open(encoding="utf-8") as stream:
        normalized = list(normalize_lines(stream))
    with local_session() as session:
        EventRepository(session).add_many(normalized)

    def override_session() -> Generator[Session, None, None]:
        with local_session() as session:
            yield session

    app.dependency_overrides[database_session] = override_session
    try:
        with TestClient(app) as client:
            queue = client.get("/api/dashboard/acquisition-candidates")
            candidate_id = queue.json()["candidates"][0]["candidate_id"]
            manifest = client.get(f"/api/dashboard/acquisition-candidates/{candidate_id}/manifest")
            missing = client.get("/api/dashboard/acquisition-candidates/candidate-missing/manifest")
    finally:
        app.dependency_overrides.clear()

    assert queue.status_code == 200
    assert queue.json()["candidate_count"] == 1
    assert queue.json()["fetcher_status"] == "disabled"
    assert manifest.status_code == 200
    assert manifest.json()["handling"]["content_included"] is False
    assert manifest.json()["candidate"]["workflow_state"] == "awaiting_manual_review"
    assert "203.0.113.20" not in manifest.text
    assert "scp://" not in manifest.text
    assert missing.status_code == 404


def test_missing_dashboard_session_returns_404(tmp_path: Path) -> None:
    engine = build_engine(f"sqlite:///{tmp_path / 'empty.db'}")
    Base.metadata.create_all(engine)
    local_session = sessionmaker(bind=engine)

    def override_session() -> Generator[Session, None, None]:
        with local_session() as session:
            yield session

    app.dependency_overrides[database_session] = override_session
    try:
        with TestClient(app) as client:
            response = client.get("/api/dashboard/sessions/missing")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 404


def test_dashboard_exposes_evidence_based_attack_chain(tmp_path: Path) -> None:
    engine = build_engine(f"sqlite:///{tmp_path / 'chain-dashboard.db'}")
    Base.metadata.create_all(engine)
    local_session = sessionmaker(bind=engine, expire_on_commit=False)
    with (FIXTURES / "cowrie_session_intelligence.jsonl").open(encoding="utf-8") as stream:
        normalized = list(normalize_lines(stream))
    with local_session() as session:
        EventRepository(session).add_many(normalized)

    def override_session() -> Generator[Session, None, None]:
        with local_session() as session:
            yield session

    app.dependency_overrides[database_session] = override_session
    try:
        with TestClient(app) as client:
            response = client.get("/api/dashboard/sessions/cowrie-intelligence-001")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert [stage["category"] for stage in payload["attack_chain"]] == [
        "access",
        "discovery",
        "staging",
        "transfer",
        "execution",
        "cleanup",
    ]
    assert payload["attack_chain"][3]["status"] == "contained"
    assert payload["timeline"][1]["event_type"] == "client_fingerprint"


def test_dashboard_exposes_geo_context_without_raw_source_ip(tmp_path: Path) -> None:
    engine = build_engine(f"sqlite:///{tmp_path / 'geo-dashboard.db'}")
    Base.metadata.create_all(engine)
    local_session = sessionmaker(bind=engine, expire_on_commit=False)
    with (FIXTURES / "cowrie_basic.jsonl").open(encoding="utf-8") as stream:
        normalized = list(normalize_lines(stream))
    with local_session() as session:
        EventRepository(session).add_many(normalized)
        events = EventRepository(session).session_events("cowrie-basic-001")

    def lookup(_ip: str) -> dict:
        return {
            "country_code": "PL",
            "country_name": "Polska",
            "asn": 64500,
            "organization": "Example Network",
            "provider": "local_mmdb",
            "scope": "network_infrastructure",
        }

    payload = dashboard_session(events, "test-pseudonym-key", lookup)

    assert payload["geo"]["country_code"] == "PL"
    assert payload["geo"]["asn"] == 64500
    assert "192.0.2.44" not in str(payload)


def test_health_requires_a_working_database(tmp_path: Path) -> None:
    engine = build_engine(f"sqlite:///{tmp_path / 'health.db'}")
    local_session = sessionmaker(bind=engine)

    def override_session() -> Generator[Session, None, None]:
        with local_session() as session:
            yield session

    app.dependency_overrides[database_session] = override_session
    try:
        with TestClient(app) as client:
            response = client.get("/health")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}


def test_health_returns_503_without_leaking_database_error() -> None:
    class BrokenSession:
        def execute(self, _statement: object) -> None:
            raise SQLAlchemyError("database password must not leak")

    def override_session():
        yield BrokenSession()

    app.dependency_overrides[database_session] = override_session
    try:
        with TestClient(app) as client:
            response = client.get("/health")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 503
    assert response.json() == {"detail": {"status": "unhealthy", "database": "unavailable"}}
    assert "password" not in response.text


def test_dashboard_gives_empty_upload_a_low_risk_label() -> None:
    event = StoredEvent(
        event_id="empty-upload",
        event_type="artifact_captured",
        timestamp=datetime(2026, 8, 29, 9, 0, tzinfo=UTC),
        sensor_id="test-sensor",
        session_id="empty-session",
        source_ip="192.0.2.20",
        data={
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "size_bytes": 0,
            "filename": "sshd",
            "origin": "direct_upload",
            "role": "unknown",
            "capture_status": "empty_upload",
        },
    )

    payload = dashboard_session([event], "test-key")

    assert payload["risk"] == {
        "score": 18,
        "level": "notice",
        "label": "Pusty lub niedokończony upload",
    }
    assert payload["detections"][0]["category"] == "empty_upload"
    assert payload["timeline"][0]["title"] == "Pusty lub niedokończony upload"
