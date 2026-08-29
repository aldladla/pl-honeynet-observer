"""Metadata-only artifact queue for the private analyst view.

This module never opens, copies, downloads, or executes an artifact. It builds
an allowlisted projection solely from validated ``artifact_captured`` events.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable, Iterable
from typing import Any

from honeynet.database import StoredEvent
from honeynet.reporting import as_utc, pseudonymize_ip

GeoIpLookup = Callable[[str], dict[str, Any] | None]
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _timestamp(event: StoredEvent) -> str:
    return as_utc(event.timestamp).isoformat().replace("+00:00", "Z")


def _artifact_id(sha256: str) -> str:
    return f"artifact-{sha256}"


def _safe_text(value: object, *, maximum: int) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = " ".join(value.split()).strip()
    return cleaned[:maximum] or None


def _safe_size(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _geo_projection(value: dict[str, Any] | None) -> dict[str, Any] | None:
    if not value:
        return None
    allowed = {"country_code", "country_name", "asn", "organization", "scope"}
    projected = {key: item for key, item in value.items() if key in allowed and item is not None}
    return projected or None


def _group_artifacts(events: Iterable[StoredEvent]) -> dict[str, list[StoredEvent]]:
    grouped: dict[str, list[StoredEvent]] = defaultdict(list)
    for event in events:
        if event.event_type != "artifact_captured":
            continue
        sha256 = str(event.data.get("sha256", "")).lower()
        if SHA256_PATTERN.fullmatch(sha256):
            grouped[sha256].append(event)
    for observations in grouped.values():
        observations.sort(key=lambda event: as_utc(event.timestamp))
    return grouped


def _artifact_summary(sha256: str, events: list[StoredEvent]) -> dict[str, Any]:
    filenames = sorted(
        {
            filename
            for event in events
            if (filename := _safe_text(event.data.get("filename"), maximum=512))
        }
    )
    origins = sorted(
        {
            origin
            for event in events
            if (origin := _safe_text(event.data.get("origin"), maximum=32))
        }
    )
    roles = sorted(
        {
            role
            for event in events
            if (role := _safe_text(event.data.get("role"), maximum=32))
        }
    )
    media_types = sorted(
        {
            media_type
            for event in events
            if (media_type := _safe_text(event.data.get("media_type"), maximum=255))
        }
    )
    sizes = sorted(
        {
            size
            for event in events
            if (size := _safe_size(event.data.get("size_bytes"))) is not None
        }
    )
    return {
        "artifact_id": _artifact_id(sha256),
        "sha256": sha256,
        "first_seen": _timestamp(events[0]),
        "last_seen": _timestamp(events[-1]),
        "observation_count": len(events),
        "session_count": len({event.session_id for event in events}),
        "sensor_count": len({event.sensor_id for event in events}),
        "filenames": filenames[:5],
        "origins": origins,
        "roles": roles,
        "media_types": media_types,
        "sizes_bytes": sizes,
        "workflow_state": "metadata_only",
        "content_exposed_by_api": False,
        "execution_allowed": False,
    }


def artifact_queue(events: Iterable[StoredEvent]) -> dict[str, Any]:
    """Return a deduplicated, metadata-only queue sorted by last observation."""

    grouped = _group_artifacts(events)
    artifacts = [_artifact_summary(sha256, observations) for sha256, observations in grouped.items()]
    artifacts.sort(key=lambda item: item["last_seen"], reverse=True)
    return {
        "status": "metadata_only",
        "artifact_count": len(artifacts),
        "observation_count": sum(item["observation_count"] for item in artifacts),
        "artifacts": artifacts,
    }


def artifact_manifest(
    events: Iterable[StoredEvent],
    artifact_id: str,
    pseudonym_key: str,
    geoip_lookup: GeoIpLookup | None = None,
) -> dict[str, Any] | None:
    """Build an allowlisted manifest without exposing or handling file content."""

    grouped = _group_artifacts(events)
    for sha256, observations in grouped.items():
        if _artifact_id(sha256) != artifact_id:
            continue
        summary = _artifact_summary(sha256, observations)
        projected_observations = []
        for event in observations:
            projected_observations.append(
                {
                    "event_id": event.event_id,
                    "timestamp": _timestamp(event),
                    "sensor_id": event.sensor_id,
                    "session_id": event.session_id,
                    "source": pseudonymize_ip(event.source_ip, pseudonym_key),
                    "geo": _geo_projection(geoip_lookup(event.source_ip))
                    if geoip_lookup
                    else None,
                    "filename": _safe_text(event.data.get("filename"), maximum=512),
                    "origin": _safe_text(event.data.get("origin"), maximum=32) or "unknown",
                    "role": _safe_text(event.data.get("role"), maximum=32) or "unknown",
                    "size_bytes": _safe_size(event.data.get("size_bytes")),
                    "media_type": _safe_text(event.data.get("media_type"), maximum=255),
                }
            )
        return {
            "manifest_version": "honeynet-artifact-metadata/v1",
            "artifact": summary,
            "observations": projected_observations,
            "handling": {
                "content_included": False,
                "network_location_included": False,
                "safe_for_static_lab": False,
                "next_step": "manual_operator_review",
                "notice": (
                    "Manifest zawiera wyłącznie metadane. Nie dowodzi złośliwości pliku "
                    "i nie upoważnia do jego pobrania ani uruchomienia."
                ),
            },
        }
    return None
