from collections.abc import Generator
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from honeynet.acquisition import acquisition_candidate_manifest, acquisition_candidate_queue
from honeynet.artifacts import artifact_manifest, artifact_queue
from honeynet.config import get_settings
from honeynet.dashboard import dashboard_overview, dashboard_session
from honeynet.database import SessionLocal, create_schema
from honeynet.geoip import GeoIpResolver
from honeynet.reporting import render_session_report
from honeynet.repository import EventRepository
from honeynet.serialization import stored_event_dict


@asynccontextmanager
async def lifespan(_: FastAPI):
    create_schema()
    yield


app = FastAPI(title="PL Honeynet Observer", version="0.1.0", lifespan=lifespan)
static_directory = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_directory), name="static")


@lru_cache
def geoip_resolver() -> GeoIpResolver:
    settings = get_settings()
    return GeoIpResolver(settings.geoip_country_db_path, settings.geoip_asn_db_path)


def database_session() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(static_directory / "index.html")


@app.get("/health")
def health(
    session: Annotated[Session, Depends(database_session)],
) -> dict[str, str]:
    """Readiness check: the API is useful only while its database responds."""

    try:
        session.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=503,
            detail={"status": "unhealthy", "database": "unavailable"},
        ) from exc
    return {"status": "ok", "database": "ok"}


@app.get("/events")
def events(
    session: Annotated[Session, Depends(database_session)],
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> list[dict]:
    records = EventRepository(session).list_events(limit=limit)
    return [stored_event_dict(record) for record in records]


@app.get("/sessions/{session_id}")
def session_details(
    session_id: str, session: Annotated[Session, Depends(database_session)]
) -> dict:
    records = EventRepository(session).session_events(session_id)
    if not records:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"session_id": session_id, "events": [stored_event_dict(record) for record in records]}


@app.get("/sessions/{session_id}/report")
def session_report(
    session_id: str, session: Annotated[Session, Depends(database_session)]
) -> dict[str, str]:
    records = EventRepository(session).session_events(session_id)
    if not records:
        raise HTTPException(status_code=404, detail="Session not found")
    report = render_session_report(records, get_settings().report_pseudonym_key)
    return {"session_id": session_id, "format": "markdown", "report": report}


@app.get("/api/dashboard/overview")
def dashboard_data(
    session: Annotated[Session, Depends(database_session)],
) -> dict:
    settings = get_settings()
    repository = EventRepository(session)
    records = repository.all_events(limit=settings.dashboard_event_limit)
    return dashboard_overview(
        records,
        settings.report_pseudonym_key,
        geoip_resolver().lookup,
        total_event_count=repository.count_events(),
        event_limit=settings.dashboard_event_limit,
    )


@app.get("/api/dashboard/sessions/{session_id}")
def dashboard_session_data(
    session_id: str,
    session: Annotated[Session, Depends(database_session)],
) -> dict:
    records = EventRepository(session).session_events(session_id)
    if not records:
        raise HTTPException(status_code=404, detail="Session not found")
    return dashboard_session(
        records,
        get_settings().report_pseudonym_key,
        geoip_resolver().lookup,
    )


@app.get("/api/dashboard/artifacts")
def dashboard_artifact_queue(
    session: Annotated[Session, Depends(database_session)],
) -> dict:
    records = EventRepository(session).artifact_events()
    return artifact_queue(records, get_settings().cowrie_artifact_root)


@app.get("/api/dashboard/artifacts/{artifact_id}/manifest")
def dashboard_artifact_manifest(
    artifact_id: str,
    session: Annotated[Session, Depends(database_session)],
) -> dict:
    records = EventRepository(session).artifact_events()
    manifest = artifact_manifest(
        records,
        artifact_id,
        get_settings().report_pseudonym_key,
        geoip_resolver().lookup,
        get_settings().cowrie_artifact_root,
    )
    if manifest is None:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return manifest


@app.get("/api/dashboard/acquisition-candidates")
def dashboard_acquisition_candidates(
    session: Annotated[Session, Depends(database_session)],
) -> dict:
    records = EventRepository(session).download_request_events()
    return acquisition_candidate_queue(records, get_settings().report_pseudonym_key)


@app.get("/api/dashboard/acquisition-candidates/{candidate_id}/manifest")
def dashboard_acquisition_candidate_manifest(
    candidate_id: str,
    session: Annotated[Session, Depends(database_session)],
) -> dict:
    records = EventRepository(session).download_request_events()
    manifest = acquisition_candidate_manifest(
        records,
        candidate_id,
        get_settings().report_pseudonym_key,
        geoip_resolver().lookup,
    )
    if manifest is None:
        raise HTTPException(status_code=404, detail="Acquisition candidate not found")
    return manifest
