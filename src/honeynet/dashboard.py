"""Sanitized projections for the analyst dashboard."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from datetime import datetime
from typing import Any

from honeynet.attack_chain import analyze_attack_chain
from honeynet.database import StoredEvent
from honeynet.detections import Detection, analyze_session
from honeynet.reporting import as_utc, pseudonymize_ip

GeoIpLookup = Callable[[str], dict[str, Any] | None]

EVENT_COPY = {
    "connection_opened": ("Połączenie otwarte", "Źródło nawiązało połączenie z sensorem."),
    "client_fingerprint": ("Profil klienta SSH", "Sensor zapisał cechy negocjacji SSH."),
    "login_attempt": ("Próba logowania", "Sensor zarejestrował próbę uwierzytelnienia."),
    "shell_opened": ("Powłoka otwarta", "Sesja osiągnęła emulowaną powłokę."),
    "command_input": ("Wprowadzono komendę", "Polecenie trafiło do emulowanego systemu."),
    "command_failed": ("Komenda nierozpoznana", "Emulowane środowisko odrzuciło polecenie."),
    "file_download_requested": (
        "Próba pobrania pliku",
        "Sesja odwołała się do zewnętrznego zasobu.",
    ),
    "artifact_captured": ("Artefakt przechwycony", "Sensor zachował metadane pliku."),
    "connection_closed": ("Połączenie zamknięte", "Sesja dobiegła końca."),
}

SAFE_DATA_FIELDS = {
    "protocol",
    "client_version",
    "hassh",
    "hassh_algorithms",
    "kex_algorithms",
    "host_key_algorithms",
    "encryption_algorithms",
    "mac_algorithms",
    "compression_algorithms",
    "username",
    "auth_method",
    "success",
    "terminal",
    "command",
    "url",
    "tool",
    "outcome",
    "destination_filename",
    "sha256",
    "size_bytes",
    "media_type",
    "filename",
    "origin",
    "role",
    "reason",
    "duration_ms",
}


def _timestamp(value: datetime) -> str:
    return as_utc(value).isoformat().replace("+00:00", "Z")


def _risk(events: list[StoredEvent], detections: list[Detection]) -> dict[str, Any]:
    types = {event.event_type for event in events}
    if "artifact_captured" in types:
        base_score, base_label = 92, "Artefakt przechwycony"
    elif "file_download_requested" in types:
        base_score, base_label = 74, "Próba dostarczenia pliku"
    elif "command_input" in types:
        base_score, base_label = 56, "Aktywna interakcja"
    elif "login_attempt" in types:
        base_score, base_label = 28, "Próba dostępu"
    else:
        base_score, base_label = 12, "Obserwacja sieciowa"

    strongest = detections[0] if detections else None
    score = max(base_score, strongest.score if strongest else 0)
    label = strongest.title if strongest and strongest.score >= base_score else base_label
    if score >= 90:
        level = "critical"
    elif score >= 70:
        level = "high"
    elif score >= 50:
        level = "elevated"
    elif score >= 25:
        level = "observed"
    else:
        level = "notice"
    return {"score": score, "level": level, "label": label}


def _session_summary(
    events: list[StoredEvent],
    key: str,
    geoip_lookup: GeoIpLookup | None = None,
) -> dict[str, Any]:
    first, last = events[0], events[-1]
    counts = Counter(event.event_type for event in events)
    detections = analyze_session(events)
    duration = max(0, int((as_utc(last.timestamp) - as_utc(first.timestamp)).total_seconds()))
    return {
        "session_id": first.session_id,
        "sensor_id": first.sensor_id,
        "source": pseudonymize_ip(first.source_ip, key),
        "geo": geoip_lookup(first.source_ip) if geoip_lookup else None,
        "started_at": _timestamp(first.timestamp),
        "ended_at": _timestamp(last.timestamp),
        "duration_seconds": duration,
        "event_count": len(events),
        "event_types": dict(sorted(counts.items())),
        "risk": _risk(events, detections),
        "detection_count": len(detections),
        "detection_categories": [item.category for item in detections],
    }


def dashboard_overview(
    events: Iterable[StoredEvent],
    key: str,
    geoip_lookup: GeoIpLookup | None = None,
    *,
    total_event_count: int | None = None,
    event_limit: int | None = None,
) -> dict[str, Any]:
    materialized = list(events)
    grouped: dict[str, list[StoredEvent]] = defaultdict(list)
    for event in materialized:
        grouped[event.session_id].append(event)

    sessions = [_session_summary(group, key, geoip_lookup) for group in grouped.values()]
    sessions.sort(key=lambda item: item["started_at"], reverse=True)
    analyzed_event_count = len(materialized)
    total = analyzed_event_count if total_event_count is None else total_event_count
    return {
        "status": "local_lab",
        "event_count": total,
        "analyzed_event_count": analyzed_event_count,
        "event_limit": event_limit,
        "truncated": total > analyzed_event_count,
        "session_count": len(sessions),
        "sensor_count": len({event.sensor_id for event in materialized}),
        "command_count": sum(event.event_type == "command_input" for event in materialized),
        "detection_count": sum(item["detection_count"] for item in sessions),
        "sessions": sessions,
    }


def dashboard_session(
    events: list[StoredEvent],
    key: str,
    geoip_lookup: GeoIpLookup | None = None,
) -> dict[str, Any]:
    summary = _session_summary(events, key, geoip_lookup)
    detections = analyze_session(events)
    attack_chain = analyze_attack_chain(events)
    timeline = []
    for event in events:
        title, description = EVENT_COPY.get(
            event.event_type, ("Zdarzenie", "Sensor zapisał zdarzenie sesji.")
        )
        if (
            event.event_type == "file_download_requested"
            and event.data.get("outcome") == "emulated"
        ):
            title = "Transfer bezpiecznie zasymulowany"
            description = (
                "Sensor nie pobrał zasobu. Utworzył nieszkodliwą atrapę, "
                "aby obserwować następny krok źródła."
            )
        safe_data = {
            field: value
            for field, value in event.data.items()
            if field in SAFE_DATA_FIELDS and value is not None
        }
        timeline.append(
            {
                "event_id": event.event_id,
                "event_type": event.event_type,
                "timestamp": _timestamp(event.timestamp),
                "title": title,
                "description": description,
                "data": safe_data,
            }
        )
    return {
        **summary,
        "attack_chain": [stage.model_dump() for stage in attack_chain],
        "detections": [detection.model_dump() for detection in detections],
        "timeline": timeline,
    }
