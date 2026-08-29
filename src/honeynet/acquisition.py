"""Metadata-only intake for remote payload acquisition candidates.

The intake is deliberately passive: it groups already stored
``file_download_requested`` events and never resolves, opens, or downloads a URL.
Network locations are represented by a keyed identifier so they are not exposed
by the dashboard API.
"""

from __future__ import annotations

import hashlib
import hmac
from collections import defaultdict
from collections.abc import Callable, Iterable
from typing import Any
from urllib.parse import urlsplit

from honeynet.database import StoredEvent
from honeynet.reporting import as_utc, pseudonymize_ip

GeoIpLookup = Callable[[str], dict[str, Any] | None]


def _timestamp(event: StoredEvent) -> str:
    return as_utc(event.timestamp).isoformat().replace("+00:00", "Z")


def _safe_text(value: object, *, maximum: int) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = " ".join(value.split()).strip()
    return cleaned[:maximum] or None


def _candidate_id(url: str, pseudonym_key: str) -> str:
    digest = hmac.new(
        pseudonym_key.encode("utf-8"),
        url.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"candidate-{digest}"


def _scheme(url: str) -> str:
    return urlsplit(url).scheme.lower()[:32] or "unknown"


def _geo_projection(value: dict[str, Any] | None) -> dict[str, Any] | None:
    if not value:
        return None
    allowed = {"country_code", "country_name", "asn", "organization", "scope"}
    projected = {key: item for key, item in value.items() if key in allowed and item is not None}
    return projected or None


def _group_candidates(events: Iterable[StoredEvent]) -> dict[str, list[StoredEvent]]:
    grouped: dict[str, list[StoredEvent]] = defaultdict(list)
    for event in events:
        if event.event_type != "file_download_requested":
            continue
        url = _safe_text(event.data.get("url"), maximum=8192)
        if url:
            grouped[url].append(event)
    for observations in grouped.values():
        observations.sort(key=lambda event: as_utc(event.timestamp))
    return grouped


def _candidate_summary(
    url: str,
    events: list[StoredEvent],
    pseudonym_key: str,
) -> dict[str, Any]:
    tools = sorted(
        {
            tool
            for event in events
            if (tool := _safe_text(event.data.get("tool"), maximum=64))
        }
    )
    outcomes = sorted(
        {
            outcome
            for event in events
            if (outcome := _safe_text(event.data.get("outcome"), maximum=16))
        }
    )
    filenames = sorted(
        {
            filename
            for event in events
            if (
                filename := _safe_text(
                    event.data.get("destination_filename"), maximum=512
                )
            )
        }
    )
    return {
        "candidate_id": _candidate_id(url, pseudonym_key),
        "first_seen": _timestamp(events[0]),
        "last_seen": _timestamp(events[-1]),
        "observation_count": len(events),
        "session_count": len({event.session_id for event in events}),
        "sensor_count": len({event.sensor_id for event in events}),
        "schemes": [_scheme(url)],
        "tools": tools,
        "outcomes": outcomes,
        "destination_filenames": filenames[:5],
        "workflow_state": "awaiting_manual_review",
        "intake_active_24_7": True,
        "content_retrieved": False,
        "automated_fetch_allowed": False,
        "network_location_exposed": False,
    }


def acquisition_candidate_queue(
    events: Iterable[StoredEvent],
    pseudonym_key: str,
) -> dict[str, Any]:
    """Return deduplicated passive-intake candidates sorted by last observation."""

    grouped = _group_candidates(events)
    candidates = [
        _candidate_summary(url, observations, pseudonym_key)
        for url, observations in grouped.items()
    ]
    candidates.sort(key=lambda item: item["last_seen"], reverse=True)
    return {
        "status": "passive_intake_only",
        "candidate_count": len(candidates),
        "observation_count": sum(item["observation_count"] for item in candidates),
        "fetcher_status": "disabled",
        "candidates": candidates,
    }


def acquisition_candidate_manifest(
    events: Iterable[StoredEvent],
    candidate_id: str,
    pseudonym_key: str,
    geoip_lookup: GeoIpLookup | None = None,
) -> dict[str, Any] | None:
    """Build an allowlisted review manifest without returning the candidate URL."""

    grouped = _group_candidates(events)
    for url, observations in grouped.items():
        if _candidate_id(url, pseudonym_key) != candidate_id:
            continue
        summary = _candidate_summary(url, observations, pseudonym_key)
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
                    "scheme": _scheme(url),
                    "tool": _safe_text(event.data.get("tool"), maximum=64),
                    "outcome": _safe_text(event.data.get("outcome"), maximum=16)
                    or "unknown",
                    "destination_filename": _safe_text(
                        event.data.get("destination_filename"), maximum=512
                    ),
                }
            )
        return {
            "manifest_version": "honeynet-acquisition-candidate/v1",
            "candidate": summary,
            "observations": projected_observations,
            "handling": {
                "network_location_included": False,
                "content_included": False,
                "fetcher_provisioned": False,
                "operator_approval_required": True,
                "next_step": "review_source_session_and_document_decision",
                "notice": (
                    "To zapis pasywnej obserwacji. Nie pobrano zawartości, a manifest "
                    "nie upoważnia do połączenia z zapisanym źródłem."
                ),
            },
        }
    return None
