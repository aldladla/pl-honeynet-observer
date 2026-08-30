"""Validated, source-agnostic event model for honeynet telemetry."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Annotated, ClassVar, Literal

from pydantic import (
    AnyUrl,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    JsonValue,
    StringConstraints,
    TypeAdapter,
    field_validator,
    model_validator,
)

Identifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
]
Port = Annotated[int, Field(ge=1, le=65535)]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F]{64}$")]


class EventType(str, Enum):
    CONNECTION_OPENED = "connection_opened"
    CLIENT_FINGERPRINT = "client_fingerprint"
    LOGIN_ATTEMPT = "login_attempt"
    SHELL_OPENED = "shell_opened"
    COMMAND_INPUT = "command_input"
    COMMAND_FAILED = "command_failed"
    COMMAND_OUTPUT = "command_output"
    FILE_DOWNLOAD_REQUESTED = "file_download_requested"
    ARTIFACT_CAPTURED = "artifact_captured"
    CONNECTION_CLOSED = "connection_closed"


class StrictPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ConnectionOpenedData(StrictPayload):
    protocol: Annotated[str, Field(min_length=1, max_length=32)]
    client_version: Annotated[str, Field(max_length=512)] | None = None


class ClientFingerprintData(StrictPayload):
    client_version: Annotated[str, Field(min_length=1, max_length=512)] | None = None
    hassh: Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F]{32,64}$")] | None = None
    hassh_algorithms: Annotated[str, Field(min_length=1, max_length=8192)] | None = None
    kex_algorithms: list[Annotated[str, Field(min_length=1, max_length=256)]] | None = None
    host_key_algorithms: list[Annotated[str, Field(min_length=1, max_length=256)]] | None = None
    encryption_algorithms: list[Annotated[str, Field(min_length=1, max_length=256)]] | None = None
    mac_algorithms: list[Annotated[str, Field(min_length=1, max_length=256)]] | None = None
    compression_algorithms: list[Annotated[str, Field(min_length=1, max_length=256)]] | None = None

    @model_validator(mode="after")
    def require_fingerprint_value(self) -> ClientFingerprintData:
        if not any(value is not None for value in self.__dict__.values()):
            raise ValueError("client fingerprint must contain at least one value")
        return self


class LoginAttemptData(StrictPayload):
    username: Annotated[str, Field(min_length=1, max_length=256)]
    auth_method: Annotated[str, Field(min_length=1, max_length=64)]
    success: bool


class ShellOpenedData(StrictPayload):
    terminal: Annotated[str, Field(min_length=1, max_length=64)] | None = None


class CommandInputData(StrictPayload):
    command: Annotated[str, Field(min_length=1, max_length=65_536)]


class CommandFailedData(StrictPayload):
    command: Annotated[str, Field(min_length=1, max_length=65_536)]
    reason: Annotated[str, Field(min_length=1, max_length=512)] | None = None


class CommandOutputData(StrictPayload):
    command: Annotated[str, Field(min_length=1, max_length=65_536)]
    tool: Annotated[str, Field(min_length=1, max_length=64)]
    stdout: Annotated[str, Field(max_length=8192)] = ""
    stderr: Annotated[str, Field(max_length=8192)] = ""
    exit_code: Annotated[int, Field(ge=0, le=255)]
    emulated: bool = True


class FileDownloadRequestedData(StrictPayload):
    url: AnyUrl
    tool: Annotated[str, Field(min_length=1, max_length=64)] | None = None
    outcome: Literal["succeeded", "failed", "emulated", "unknown"] | None = None
    destination_filename: Annotated[str, Field(min_length=1, max_length=512)] | None = None
    phase: Literal["primary", "fallback"] | None = None
    execution_intended: bool | None = None
    cleanup_intended: bool | None = None


class ArtifactCapturedData(StrictPayload):
    sha256: Sha256
    size_bytes: Annotated[int, Field(ge=0)] | None = None
    media_type: Annotated[str, Field(min_length=1, max_length=255)] | None = None
    filename: Annotated[str, Field(min_length=1, max_length=512)] | None = None
    origin: Literal[
        "direct_upload", "remote_fetch", "shell_redirect", "stdin_capture", "unknown"
    ] = "unknown"
    role: Literal["key", "config", "script", "archive", "executable", "unknown"] = "unknown"
    capture_status: Literal["complete", "empty_upload", "incomplete_transfer", "unknown"] | None = (
        None
    )


class ConnectionClosedData(StrictPayload):
    reason: Annotated[str, Field(min_length=1, max_length=256)]
    duration_ms: Annotated[int, Field(ge=0)] | None = None


class Event(BaseModel):
    """Canonical event accepted by collectors and emitted by normalizers.

    ``model_validate`` accepts a Python mapping. ``model_dump(mode="json")``
    produces a JSON-safe record suitable for persistence or reporting.
    """

    model_config = ConfigDict(extra="forbid")

    event_id: Identifier
    event_type: EventType
    timestamp: datetime
    sensor_id: Identifier
    session_id: Identifier
    source_ip: IPvAnyAddress
    source_port: Port | None = None
    destination_ip: IPvAnyAddress | None = None
    destination_port: Port | None = None
    data: dict[str, JsonValue] = Field(default_factory=dict)
    source_event: dict[str, JsonValue] | None = None

    _payload_adapters: ClassVar[dict[EventType, TypeAdapter[StrictPayload]]] = {
        EventType.CONNECTION_OPENED: TypeAdapter(ConnectionOpenedData),
        EventType.CLIENT_FINGERPRINT: TypeAdapter(ClientFingerprintData),
        EventType.LOGIN_ATTEMPT: TypeAdapter(LoginAttemptData),
        EventType.SHELL_OPENED: TypeAdapter(ShellOpenedData),
        EventType.COMMAND_INPUT: TypeAdapter(CommandInputData),
        EventType.COMMAND_FAILED: TypeAdapter(CommandFailedData),
        EventType.COMMAND_OUTPUT: TypeAdapter(CommandOutputData),
        EventType.FILE_DOWNLOAD_REQUESTED: TypeAdapter(FileDownloadRequestedData),
        EventType.ARTIFACT_CAPTURED: TypeAdapter(ArtifactCapturedData),
        EventType.CONNECTION_CLOSED: TypeAdapter(ConnectionClosedData),
    }

    @field_validator("timestamp")
    @classmethod
    def require_utc_timestamp(cls, value: datetime) -> datetime:
        """Reject naive datetimes and normalize aware timestamps to UTC."""

        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_event_payload(self) -> Event:
        """Validate and JSON-normalize the payload selected by event type."""

        adapter = self._payload_adapters[self.event_type]
        payload = adapter.validate_python(self.data)
        self.data = payload.model_dump(mode="json", exclude_none=True)
        if self.event_type is EventType.ARTIFACT_CAPTURED:
            self.data["sha256"] = str(self.data["sha256"]).lower()
        return self


def parse_event(value: object) -> Event:
    """Compatibility helper for code that prefers a parsing function."""

    return Event.model_validate(value)
