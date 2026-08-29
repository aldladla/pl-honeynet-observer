"""Deterministic normalization of Cowrie JSON events.

This module only parses metadata. It never opens, downloads, or executes artifacts.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Iterator, Mapping
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from honeynet.models import Event, EventType
from honeynet.privacy import redact_text, sanitize_json


def _event_id(record: Mapping[str, Any], projection: str) -> str:
    identity = {
        "eventid": record.get("eventid"),
        "session": record.get("session"),
        "timestamp": record.get("timestamp"),
        "projection": projection,
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    return f"cowrie-{hashlib.sha256(encoded).hexdigest()[:32]}"


def _base(record: Mapping[str, Any], event_type: EventType, projection: str) -> dict[str, Any]:
    return {
        "event_id": _event_id(record, projection),
        "event_type": event_type,
        "timestamp": record["timestamp"],
        "sensor_id": record["sensor"],
        "session_id": record["session"],
        "source_ip": record["src_ip"],
        "source_port": record.get("src_port"),
        "destination_ip": record.get("dst_ip"),
        "destination_port": record.get("dst_port"),
        # Cowrie records are attacker-controlled and may contain credentials.
        # Keep their useful structure, but never retain likely secrets verbatim.
        "source_event": sanitize_json(record),
    }


def _algorithm_list(value: Any) -> list[str] | None:
    if isinstance(value, str):
        items = [item.strip() for item in value.split(",") if item.strip()]
    elif isinstance(value, list):
        items = [str(item).strip() for item in value if str(item).strip()]
    else:
        return None
    return items[:128] or None


def _safe_filename(record: Mapping[str, Any]) -> str | None:
    for field in ("filename", "outfile", "destfile"):
        value = record.get(field)
        if isinstance(value, str) and value.strip():
            normalized = value.strip().replace("\\", "/")
            return redact_text(PurePosixPath(normalized).name)[:512] or None
    return None


def _download_tool(url: str) -> str | None:
    scheme = urlsplit(url).scheme.lower()
    return scheme if scheme in {"http", "https", "ftp", "tftp", "scp", "sftp"} else None


def _artifact_origin(source_type: str, url: str | None) -> str:
    if source_type == "cowrie.session.file_upload":
        return "direct_upload"
    normalized = (url or "").strip().lower()
    if normalized.startswith(("stdin:", "stdin/")) or normalized == "stdin":
        return "stdin_capture"
    if normalized.startswith(("file:", "shell:")) or not normalized:
        return "shell_redirect"
    if urlsplit(normalized).scheme in {"http", "https", "ftp", "tftp", "scp", "sftp"}:
        return "remote_fetch"
    return "unknown"


def _artifact_role(filename: str | None) -> str:
    if not filename:
        return "unknown"
    lowered = filename.lower()
    if lowered.endswith((".key", ".pem", ".ppk")) or "id_rsa" in lowered:
        return "key"
    if lowered.endswith((".conf", ".cfg", ".ini", ".yaml", ".yml", ".json")):
        return "config"
    if lowered.endswith((".sh", ".py", ".pl", ".ps1")):
        return "script"
    if lowered.endswith((".zip", ".tar", ".gz", ".bz2", ".xz", ".7z")):
        return "archive"
    if lowered.endswith((".exe", ".dll", ".elf", ".bin")):
        return "executable"
    return "unknown"


def normalize_cowrie(record: Mapping[str, Any]) -> list[Event]:
    """Project one Cowrie JSON record into zero, one, or two canonical events."""

    source_type = record.get("eventid")
    projected: list[dict[str, Any]] = []

    if source_type == "cowrie.session.connect":
        event = _base(record, EventType.CONNECTION_OPENED, "connection")
        event["data"] = {"protocol": str(record.get("protocol", "unknown"))}
        projected.append(event)

    elif source_type == "cowrie.client.version":
        version = record.get("version")
        if isinstance(version, str) and version.strip():
            event = _base(record, EventType.CLIENT_FINGERPRINT, "client-version")
            event["data"] = {"client_version": redact_text(version.strip())[:512]}
            projected.append(event)

    elif source_type == "cowrie.client.kex":
        aliases = {
            "kex_algorithms": ("kexAlgs", "kex_algorithms"),
            "host_key_algorithms": ("keyAlgs", "host_key_algorithms"),
            "encryption_algorithms": ("encCS", "encryption_algorithms"),
            "mac_algorithms": ("macCS", "mac_algorithms"),
            "compression_algorithms": ("compCS", "compression_algorithms"),
        }
        data: dict[str, Any] = {}
        if isinstance(record.get("hassh"), str) and record["hassh"].strip():
            data["hassh"] = record["hassh"].strip().lower()
        if isinstance(record.get("hasshAlgorithms"), str):
            data["hassh_algorithms"] = record["hasshAlgorithms"][:8192]
        for target, fields in aliases.items():
            for field in fields:
                algorithms = _algorithm_list(record.get(field))
                if algorithms:
                    data[target] = algorithms
                    break
        if data:
            event = _base(record, EventType.CLIENT_FINGERPRINT, "client-kex")
            event["data"] = data
            projected.append(event)

    elif source_type in {"cowrie.login.failed", "cowrie.login.success"}:
        event = _base(record, EventType.LOGIN_ATTEMPT, "login")
        auth_method = "publickey" if record.get("key") or record.get("fingerprint") else "password"
        event["data"] = {
            "username": str(record.get("username", "unknown")),
            "auth_method": auth_method,
            "success": source_type == "cowrie.login.success",
        }
        projected.append(event)

    elif source_type == "cowrie.log.open":
        event = _base(record, EventType.SHELL_OPENED, "shell")
        event["data"] = {}
        projected.append(event)

    elif source_type in {"cowrie.command.input", "cowrie.session.input"}:
        command = record.get("input")
        if isinstance(command, str) and command:
            event = _base(record, EventType.COMMAND_INPUT, "command")
            event["data"] = {"command": redact_text(command)}
            projected.append(event)

    elif source_type == "cowrie.command.failed":
        command = record.get("input")
        if isinstance(command, str) and command:
            event = _base(record, EventType.COMMAND_FAILED, "command-failed")
            event["data"] = {
                "command": redact_text(command),
                "reason": redact_text(str(record.get("message", "command failed")))[:512],
            }
            projected.append(event)

    elif source_type == "cowrie.session.file_download.simulated":
        if record.get("url"):
            url = redact_text(str(record["url"]))
            event = _base(record, EventType.FILE_DOWNLOAD_REQUESTED, "download-simulated")
            event["data"] = {
                "url": url,
                "tool": str(record.get("tool") or _download_tool(url) or "transfer")[:64],
                "outcome": "emulated",
                "destination_filename": _safe_filename(record),
            }
            projected.append(event)

    elif source_type == "cowrie.session.file_download.failed":
        if record.get("url"):
            url = redact_text(str(record["url"]))
            event = _base(record, EventType.FILE_DOWNLOAD_REQUESTED, "download-request")
            event["data"] = {
                "url": url,
                "tool": _download_tool(url),
                "outcome": "failed",
                "destination_filename": _safe_filename(record),
            }
            projected.append(event)

    elif source_type == "cowrie.session.file_download":
        origin = _artifact_origin(source_type, str(record.get("url", "")))
        if record.get("url") and origin == "remote_fetch":
            url = redact_text(str(record["url"]))
            request = _base(record, EventType.FILE_DOWNLOAD_REQUESTED, "download-request")
            request["data"] = {
                "url": url,
                "tool": _download_tool(url),
                "outcome": "succeeded",
                "destination_filename": _safe_filename(record),
            }
            projected.append(request)
        if record.get("shasum"):
            filename = _safe_filename(record)
            artifact = _base(record, EventType.ARTIFACT_CAPTURED, "download-artifact")
            artifact["data"] = {
                "sha256": record["shasum"],
                "size_bytes": record.get("size"),
                "filename": filename,
                "origin": origin,
                "role": _artifact_role(filename),
            }
            projected.append(artifact)

    elif source_type == "cowrie.session.file_upload" and record.get("shasum"):
        filename = _safe_filename(record)
        event = _base(record, EventType.ARTIFACT_CAPTURED, "upload-artifact")
        event["data"] = {
            "sha256": record["shasum"],
            "size_bytes": record.get("size"),
            "filename": filename,
            "origin": "direct_upload",
            "role": _artifact_role(filename),
        }
        projected.append(event)

    elif source_type == "cowrie.session.closed":
        event = _base(record, EventType.CONNECTION_CLOSED, "closed")
        event["data"] = {
            "reason": str(record.get("message", "connection closed"))[:256],
            "duration_ms": record.get("duration_ms"),
        }
        projected.append(event)

    return [Event.model_validate(item) for item in projected]


def normalize_lines(lines: Iterable[str]) -> Iterator[Event]:
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            if not isinstance(record, dict):
                raise TypeError("rekord nie jest obiektem JSON")
            yield from normalize_cowrie(record)
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Niepoprawny rekord Cowrie w linii {line_number}: {exc}") from exc
