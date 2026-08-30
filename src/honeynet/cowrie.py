"""Deterministic normalization of Cowrie JSON events.

This module only parses metadata. It never opens, downloads, or executes artifacts.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from collections.abc import Iterable, Iterator, Mapping
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from honeynet.models import Event, EventType
from honeynet.privacy import redact_text, sanitize_json

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
URL_PATTERN = re.compile(r"(?P<url>(?:https?|ftp|tftp)://[^\s'\";|&)]+)", re.IGNORECASE)
SCP_SOURCE_PATTERN = re.compile(
    r"^(?:(?P<user>[^@\s:]+)@)?(?P<host>\[[^]]+\]|[^:\s]+):(?P<path>.+)$"
)


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


def _artifact_metadata(record: Mapping[str, Any]) -> tuple[int | None, str]:
    raw_size = record.get("size")
    size = raw_size if isinstance(raw_size, int) and not isinstance(raw_size, bool) else None
    sha256 = str(record.get("shasum", "")).lower()
    if sha256 == EMPTY_SHA256:
        return 0, "empty_upload"
    if size == 0:
        return 0, "incomplete_transfer"
    if size is not None:
        return size, "complete"
    return None, "unknown"


def _shell_tokens(fragment: str) -> list[str]:
    try:
        return shlex.split(fragment, comments=False, posix=True)
    except ValueError:
        return fragment.split()


def _has_cleanup(command: str) -> bool:
    return bool(re.search(r"(?:^|[;&|]\s*)rm\s+(?:-[A-Za-z]+\s+)*[^;&|]+", command))


def _execution_targets(command: str) -> set[str]:
    targets: set[str] = set()
    for match in re.finditer(
        r"(?:^|[;&|]\s*)(?:chmod\s+\+x\s+)?(?:(?:\./|/)?(?P<target>[\w./-]+))",
        command,
    ):
        target = PurePosixPath(match.group("target")).name
        if target and target not in {"chmod", "rm", "wget", "curl", "scp"}:
            targets.add(target)
    for match in re.finditer(r"\|\s*(?:ba|z|k)?sh(?:\s|$)", command):
        if match:
            targets.add("<stdin>")
    return targets


def _scp_request(command: str) -> dict[str, Any] | None:
    match = re.search(
        r"(?:^|[;&|]\s*)(?:if\s+)?scp\s+(?P<body>.*?)(?=\s*(?:;|&&|\|\||$))",
        command,
    )
    if not match:
        return None
    tokens = _shell_tokens(match.group("body"))
    operands: list[str] = []
    skip_next = False
    options_with_value = {"-B", "-c", "-D", "-F", "-i", "-J", "-l", "-o", "-P", "-S", "-X"}
    for token in tokens:
        if skip_next:
            skip_next = False
            continue
        if token in options_with_value:
            skip_next = True
            continue
        if token.startswith("-"):
            continue
        operands.append(token)
    if len(operands) < 2:
        return None
    source, destination = operands[-2], operands[-1]
    parsed = SCP_SOURCE_PATTERN.match(source)
    if not parsed:
        return None
    host = parsed.group("host").strip("[]")
    remote_path = parsed.group("path").lstrip("/")
    safe_url = f"scp://{host}/{remote_path}"
    filename = PurePosixPath(destination.replace("\\", "/")).name or None
    execution_targets = _execution_targets(command)
    return {
        "url": redact_text(safe_url),
        "tool": "scp",
        "outcome": "unknown",
        "destination_filename": redact_text(filename)[:512] if filename else None,
        "phase": "primary",
        "execution_intended": bool(filename and filename in execution_targets),
        "cleanup_intended": _has_cleanup(command),
    }


def _http_requests(command: str) -> list[dict[str, Any]]:
    requests: list[dict[str, Any]] = []
    execution_targets = _execution_targets(command)
    cleanup = _has_cleanup(command)
    for match in re.finditer(
        r"(?:^|[;&|(]\s*)(?P<tool>curl|wget)\b(?P<body>[^;&|)]*)", command, re.IGNORECASE
    ):
        tool = match.group("tool").lower()
        body = match.group("body")
        url_match = URL_PATTERN.search(body)
        if not url_match:
            continue
        tokens = _shell_tokens(body)
        destination = None
        output_flags = {"-o", "--output"} if tool == "curl" else {"-O", "-o", "--output-document"}
        for index, token in enumerate(tokens[:-1]):
            if token in output_flags:
                destination = PurePosixPath(tokens[index + 1].replace("\\", "/")).name
                break
        piped_to_shell = bool(
            re.search(r"\|\s*(?:ba|z|k)?sh(?:\s|$)", command[match.start() :], re.IGNORECASE)
        )
        requests.append(
            {
                "url": redact_text(url_match.group("url")),
                "tool": tool,
                "outcome": "unknown",
                "destination_filename": redact_text(destination)[:512] if destination else None,
                "phase": "fallback"
                if re.search(r"\b(?:else|fallback)\b|\|\|", command[: match.start()], re.IGNORECASE)
                else "primary",
                "execution_intended": piped_to_shell
                or bool(destination and destination in execution_targets),
                "cleanup_intended": cleanup,
            }
        )
    return requests


def _compound_transfer_requests(command: str) -> list[dict[str, Any]]:
    requests: list[dict[str, Any]] = []
    if request := _scp_request(command):
        requests.append(request)
    requests.extend(_http_requests(command))
    # Simple transfer commands already produce native Cowrie transfer events.
    # This projection is deliberately reserved for compound fallback chains
    # that Cowrie otherwise records only as one opaque command_input.
    return requests if len(requests) >= 2 else []


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
            for index, request_data in enumerate(_compound_transfer_requests(command)):
                request = _base(
                    record,
                    EventType.FILE_DOWNLOAD_REQUESTED,
                    f"command-transfer-{index}",
                )
                request["data"] = request_data
                projected.append(request)

    elif source_type == "cowrie.command.failed":
        command = record.get("input")
        if isinstance(command, str) and command:
            event = _base(record, EventType.COMMAND_FAILED, "command-failed")
            event["data"] = {
                "command": redact_text(command),
                "reason": redact_text(str(record.get("message", "command failed")))[:512],
            }
            projected.append(event)

    elif source_type == "cowrie.command.output.emulated":
        command = record.get("input")
        tool = record.get("tool")
        if isinstance(command, str) and command and isinstance(tool, str) and tool:
            event = _base(record, EventType.COMMAND_OUTPUT, "command-output-emulated")
            event["data"] = {
                "command": redact_text(command),
                "tool": redact_text(tool)[:64],
                "stdout": redact_text(str(record.get("stdout", "")))[:8192],
                "stderr": redact_text(str(record.get("stderr", "")))[:8192],
                "exit_code": int(record.get("exit_code", 0)),
                "emulated": True,
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
            size_bytes, capture_status = _artifact_metadata(record)
            artifact = _base(record, EventType.ARTIFACT_CAPTURED, "download-artifact")
            artifact["data"] = {
                "sha256": record["shasum"],
                "size_bytes": size_bytes,
                "filename": filename,
                "origin": origin,
                "role": _artifact_role(filename),
                "capture_status": capture_status,
            }
            projected.append(artifact)

    elif source_type == "cowrie.session.file_upload" and record.get("shasum"):
        filename = _safe_filename(record)
        size_bytes, capture_status = _artifact_metadata(record)
        event = _base(record, EventType.ARTIFACT_CAPTURED, "upload-artifact")
        event["data"] = {
            "sha256": record["shasum"],
            "size_bytes": size_bytes,
            "filename": filename,
            "origin": "direct_upload",
            "role": _artifact_role(filename),
            "capture_status": capture_status,
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
