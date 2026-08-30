"""Evidence-based reconstruction of an observed honeypot session.

The analyzer works only on normalized metadata. A command is treated as attacker
intent, never as proof that the emulated operating system performed the action.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Literal

from honeynet.artifact_state import is_meaningful_artifact
from honeynet.database import StoredEvent
from honeynet.reporting import as_utc

EvidenceStatus = Literal["observed", "attempted", "contained", "unknown"]


@dataclass(frozen=True)
class ChainEvidence:
    event_id: str
    timestamp: str
    value: str


@dataclass(frozen=True)
class AttackStage:
    stage_id: str
    order: int
    category: str
    title: str
    status: EvidenceStatus
    confidence: Literal["low", "medium", "high"]
    summary: str
    evidence: tuple[ChainEvidence, ...]

    def model_dump(self) -> dict[str, object]:
        return asdict(self)


def _timestamp(value: datetime) -> str:
    return as_utc(value).isoformat().replace("+00:00", "Z")


def _evidence(event: StoredEvent, value: str) -> ChainEvidence:
    return ChainEvidence(event.event_id, _timestamp(event.timestamp), value[:500])


def _commands(events: list[StoredEvent]) -> list[tuple[StoredEvent, str]]:
    result = []
    for event in events:
        if event.event_type not in {"command_input", "command_failed"}:
            continue
        command = event.data.get("command")
        if isinstance(command, str) and command:
            result.append((event, command))
    return result


def _matching_commands(
    commands: list[tuple[StoredEvent, str]], *patterns: str
) -> tuple[ChainEvidence, ...]:
    compiled = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    return tuple(
        _evidence(event, command)
        for event, command in commands
        if any(pattern.search(command) for pattern in compiled)
    )[:5]


def _stage(
    session_id: str,
    order: int,
    category: str,
    title: str,
    status: EvidenceStatus,
    confidence: Literal["low", "medium", "high"],
    summary: str,
    evidence: tuple[ChainEvidence, ...],
) -> AttackStage:
    return AttackStage(
        stage_id=f"{session_id}:{category}",
        order=order,
        category=category,
        title=title,
        status=status,
        confidence=confidence,
        summary=summary,
        evidence=evidence,
    )


def analyze_attack_chain(events: list[StoredEvent]) -> list[AttackStage]:
    """Return ordered stages without claiming effects absent from telemetry."""

    if not events:
        return []
    session_id = events[0].session_id
    commands = _commands(events)
    stages: list[AttackStage] = []

    successful_logins = [
        event
        for event in events
        if event.event_type == "login_attempt" and event.data.get("success") is True
    ]
    connections = [event for event in events if event.event_type == "connection_opened"]
    access_events = successful_logins or connections
    if access_events:
        value = (
            "Udane logowanie do emulowanej usługi" if successful_logins else "Połączenie z usługą"
        )
        stages.append(
            _stage(
                session_id,
                10,
                "access",
                "Kontakt i dostęp",
                "observed",
                "high",
                "Sensor bezpośrednio zarejestrował kontakt z usługą.",
                tuple(_evidence(event, value) for event in access_events[:5]),
            )
        )

    discovery = _matching_commands(
        commands,
        r"(?:^|[;&|($]\s*)(?:(?:/[a-z0-9_.+-]+)+/)?(?:uname|id|whoami|hostname|lscpu|free|df|mount|ps|last|w|who)\b",
        r"(?:^|[;&|]\s*)(?:ifconfig|netstat|route|arp|ip|ss)\b",
        r"/etc/(?:os-release|issue|passwd|resolv\.conf|hosts)\b",
        r"\b(?:cowrie|kippo|honeypot|systemd-detect-virt|virt-what|dmidecode)\b",
    )
    if discovery:
        stages.append(
            _stage(
                session_id,
                20,
                "discovery",
                "Rozpoznanie środowiska",
                "observed",
                "high",
                "Polecenia rozpoznawcze zostały wprowadzone do emulowanej powłoki.",
                discovery,
            )
        )

    staging_artifacts = [
        event
        for event in events
        if event.event_type == "artifact_captured"
        and event.data.get("origin") in {"direct_upload", "shell_redirect", "stdin_capture"}
        and is_meaningful_artifact(event.data)
    ]
    staging_commands = _matching_commands(
        commands,
        r"(?:^|[;&|]\s*)(?:mkdir|mktemp)\b",
        r"(?:^|[;&|]\s*)(?:echo|printf|cat|base64)\b[^\n]*(?:>|\btee\b)",
    )
    if staging_artifacts or staging_commands:
        evidence = (
            tuple(
                _evidence(
                    event,
                    f"Artefakt {event.data.get('origin', 'unknown')}: "
                    f"{event.data.get('filename', event.data.get('sha256', 'bez nazwy'))}",
                )
                for event in staging_artifacts[:5]
            )
            or staging_commands
        )
        status: EvidenceStatus = "observed" if staging_artifacts else "attempted"
        stages.append(
            _stage(
                session_id,
                30,
                "staging",
                "Przygotowanie plików i narzędzi",
                status,
                "high" if staging_artifacts else "medium",
                "Sensor zarejestrował przygotowanie zasobów przed dalszym działaniem.",
                evidence,
            )
        )

    download_events = [event for event in events if event.event_type == "file_download_requested"]
    remote_artifacts = [
        event
        for event in events
        if event.event_type == "artifact_captured"
        and event.data.get("origin") == "remote_fetch"
        and is_meaningful_artifact(event.data)
    ]
    transfer_commands = _matching_commands(
        commands,
        r"(?:^|[;&|]\s*)(?:curl|wget|tftp|ftpget|scp|sftp)\b",
    )
    if download_events or remote_artifacts or transfer_commands:
        emulated = any(event.data.get("outcome") == "emulated" for event in download_events)
        failed = any(event.data.get("outcome") == "failed" for event in download_events)
        if remote_artifacts or any(
            event.data.get("outcome") == "succeeded" for event in download_events
        ):
            status = "observed"
            summary = "Telemetria Cowrie potwierdza zarejestrowanie transferu lub jego artefaktu."
            confidence = "high"
        elif emulated:
            status = "contained"
            summary = (
                "Sensor zasymulował powodzenie transferu bez pobierania danych z Internetu. "
                "Pozwala to obserwować kolejne polecenia źródła bez wykonania payloadu."
            )
            confidence = "high"
        elif failed:
            status = "contained"
            summary = (
                "Próba transferu została zarejestrowana jako nieudana w emulowanym środowisku."
            )
            confidence = "high"
        else:
            status = "attempted"
            summary = "Komenda wskazuje zamiar transferu, ale nie potwierdza pobrania danych."
            confidence = "medium"
        evidence = (
            tuple(
                _evidence(
                    event,
                    f"{event.data.get('outcome', 'unknown')}: {event.data.get('url', 'transfer')}",
                )
                for event in download_events[:5]
            )
            or tuple(
                _evidence(event, f"Przechwycono hash {event.data.get('sha256')}")
                for event in remote_artifacts[:5]
            )
            or transfer_commands
        )
        stages.append(
            _stage(
                session_id,
                40,
                "transfer",
                "Transfer zewnętrznego zasobu",
                status,
                confidence,
                summary,
                evidence,
            )
        )

    execution = _matching_commands(
        commands,
        r"\bchmod\s+(?:\+x|[0-7]*7[0-7]*)\b",
        r"(?:^|[;&|]\s*)(?:sh|bash|dash|python\d*|perl)\b",
        r"\|\s*(?:sh|bash|dash)\b",
        r"(?:^|[;&|]\s*)(?:\./|/tmp/|/var/tmp/)[^\s;&|]+",
    )
    if execution:
        failed_ids = {event.event_id for event in events if event.event_type == "command_failed"}
        emulated_transfer = any(
            event.event_type == "file_download_requested"
            and event.data.get("outcome") == "emulated"
            for event in events
        )
        if emulated_transfer:
            status = "contained"
            confidence = "high"
            summary = (
                "Do emulowanego interpretera trafiła wyłącznie nieszkodliwa atrapa "
                "zakończona `exit 0`; kod wskazany przez źródło nie został pobrany ani wykonany."
            )
        elif any(item.event_id in failed_ids for item in execution):
            status = "contained"
            confidence = "medium"
            summary = (
                "Polecenie wskazuje zamiar wykonania, lecz emulowane środowisko "
                "zarejestrowało jego niepowodzenie i brak uruchomienia procesu."
            )
        else:
            status = "attempted"
            confidence = "medium"
            summary = (
                "Polecenie wskazuje zamiar wykonania; nie jest dowodem uruchomienia "
                "procesu na hoście."
            )
        stages.append(
            _stage(
                session_id,
                50,
                "execution",
                "Próba wykonania",
                status,
                confidence,
                summary,
                execution,
            )
        )

    persistence = _matching_commands(
        commands,
        r"\b(?:crontab|systemctl\s+enable)\b",
        r"/(?:etc/cron|\.ssh/authorized_keys)\b",
    )
    if persistence:
        stages.append(
            _stage(
                session_id,
                60,
                "persistence",
                "Próba utrzymania dostępu",
                "attempted",
                "medium",
                "Komendy pasują do mechanizmów trwałości, ale ich skutku nie potwierdzono.",
                persistence,
            )
        )

    cleanup = _matching_commands(
        commands,
        r"(?:^|[;&|]\s*)(?:rm|shred)\s+",
        r"\bhistory\s+-c\b",
        r"\bunset\s+HISTFILE\b",
    )
    if cleanup:
        stages.append(
            _stage(
                session_id,
                70,
                "cleanup",
                "Próba usunięcia śladów",
                "attempted",
                "medium",
                "Zaobserwowano polecenie czyszczenia; nie zakładamy, że zostało wykonane.",
                cleanup,
            )
        )

    return sorted(stages, key=lambda item: item.order)
