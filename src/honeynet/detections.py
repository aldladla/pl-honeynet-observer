"""Explainable, metadata-only behavior detections for honeypot sessions."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime

from honeynet.database import StoredEvent
from honeynet.reporting import as_utc


@dataclass(frozen=True)
class DetectionEvidence:
    event_id: str
    timestamp: str
    value: str


@dataclass(frozen=True)
class Detection:
    detection_id: str
    category: str
    severity: str
    confidence: str
    score: int
    title: str
    summary: str
    evidence: tuple[DetectionEvidence, ...]

    def model_dump(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class CommandRule:
    category: str
    severity: str
    confidence: str
    score: int
    title: str
    summary: str
    patterns: tuple[re.Pattern[str], ...]


def _patterns(*expressions: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(expression, re.IGNORECASE) for expression in expressions)


COMMAND_RULES = (
    CommandRule(
        category="honeypot_probe",
        severity="high",
        confidence="medium",
        score=68,
        title="Próba rozpoznania honeypota",
        summary=(
            "Źródło sprawdza ślady emulacji, konteneryzacji albo bezpośrednio szuka "
            "nazw znanych honeypotów. To sygnał fingerprintingu, nie dowód jego skuteczności."
        ),
        patterns=_patterns(
            r"\b(?:cowrie|kippo|honeypot)\b",
            r"\b(?:systemd-detect-virt|virt-what|dmidecode)\b",
            r"(?:^|[;&|]\s*)(?:cat|grep|ls|stat|test)\b[^\n]*(?:/\.dockerenv|/proc/1/(?:cgroup|mountinfo|status)|/sys/class/dmi)",
        ),
    ),
    CommandRule(
        category="payload_delivery",
        severity="high",
        confidence="high",
        score=76,
        title="Próba dostarczenia payloadu",
        summary=(
            "Polecenie używa typowego narzędzia transferu. Sensor rejestruje wyłącznie "
            "metadane i nie wykonuje pobranego pliku."
        ),
        patterns=_patterns(r"(?:^|[;&|]\s*)(?:curl|wget|tftp|ftpget)\b"),
    ),
    CommandRule(
        category="execution_preparation",
        severity="high",
        confidence="medium",
        score=82,
        title="Przygotowanie wykonania lub utrzymania dostępu",
        summary=(
            "Sekwencja zawiera zmianę praw, dekodowanie, uruchamianie w tle albo próbę "
            "utworzenia trwałego mechanizmu startowego."
        ),
        patterns=_patterns(
            r"\bchmod\s+(?:\+x|[0-7]*7[0-7]*)\b",
            r"\bbase64\b[^\n]*(?:-d|--decode)\b",
            r"\b(?:nohup|setsid|crontab)\b",
            r"\bsystemctl\s+(?:enable|start)\b",
        ),
    ),
    CommandRule(
        category="network_discovery",
        severity="medium",
        confidence="medium",
        score=61,
        title="Rozpoznanie sieci",
        summary=(
            "Źródło odpytuje interfejsy, trasy, połączenia lub konfigurację DNS "
            "emulowanego systemu."
        ),
        patterns=_patterns(
            r"(?:^|[;&|]\s*)(?:ifconfig|netstat|route|arp)\b",
            r"(?:^|[;&|]\s*)(?:ip|ss)\s+(?:a|addr|address|r|route|l|link|-[a-z]*[anrtulp]+)\b",
            r"(?:^|[;&|]\s*)hostname\s+-I\b",
            r"/etc/(?:resolv\.conf|hosts)\b",
        ),
    ),
    CommandRule(
        category="system_discovery",
        severity="medium",
        confidence="high",
        score=58,
        title="Rozpoznanie systemu",
        summary=(
            "Źródło zbiera podstawowe informacje o systemie, użytkowniku, procesach "
            "lub zasobach przed podjęciem dalszych działań."
        ),
        patterns=_patterns(
            r"(?:^|[;&|]\s*)(?:uname|id|whoami|hostname|lscpu|free|df|mount|ps|last|w|who)\b",
            r"(?:^|[;&|]\s*)cat\b[^\n]*/etc/(?:os-release|issue|passwd)\b",
            r"(?:^|[;&|]\s*)(?:env|printenv)\b",
        ),
    ),
)


def _timestamp(value: datetime) -> str:
    return as_utc(value).isoformat().replace("+00:00", "Z")


def _command_evidence(
    events: list[StoredEvent], rule: CommandRule
) -> tuple[DetectionEvidence, ...]:
    matches: list[DetectionEvidence] = []
    for event in events:
        if event.event_type != "command_input":
            continue
        command = event.data.get("command")
        if not isinstance(command, str):
            continue
        if any(pattern.search(command) for pattern in rule.patterns):
            matches.append(
                DetectionEvidence(
                    event_id=event.event_id,
                    timestamp=_timestamp(event.timestamp),
                    value=command[:500],
                )
            )
    return tuple(matches[:5])


def _event_evidence(
    events: list[StoredEvent], event_type: str, value: str
) -> tuple[DetectionEvidence, ...]:
    return tuple(
        DetectionEvidence(event.event_id, _timestamp(event.timestamp), value)
        for event in events
        if event.event_type == event_type
    )[:5]


def analyze_session(events: list[StoredEvent]) -> list[Detection]:
    if not events:
        return []

    session_id = events[0].session_id
    detections: list[Detection] = []
    for rule in COMMAND_RULES:
        evidence = _command_evidence(events, rule)
        if evidence:
            detections.append(
                Detection(
                    detection_id=f"{session_id}:{rule.category}",
                    category=rule.category,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    score=rule.score,
                    title=rule.title,
                    summary=rule.summary,
                    evidence=evidence,
                )
            )

    download_evidence = _event_evidence(events, "file_download_requested", "Żądanie pobrania")
    if download_evidence and not any(item.category == "payload_delivery" for item in detections):
        detections.append(
            Detection(
                detection_id=f"{session_id}:payload_delivery",
                category="payload_delivery",
                severity="high",
                confidence="high",
                score=76,
                title="Próba dostarczenia payloadu",
                summary="Sensor zarejestrował odwołanie do zewnętrznego zasobu.",
                evidence=download_evidence,
            )
        )

    artifact_evidence = _event_evidence(events, "artifact_captured", "Metadane artefaktu")
    if artifact_evidence:
        detections.append(
            Detection(
                detection_id=f"{session_id}:artifact_captured",
                category="artifact_captured",
                severity="critical",
                confidence="high",
                score=92,
                title="Artefakt przechwycony",
                summary=(
                    "Sensor zachował metadane artefaktu. Sam plik nie został uruchomiony "
                    "przez pipeline analityczny."
                ),
                evidence=artifact_evidence,
            )
        )

    failed_logins = [
        event
        for event in events
        if event.event_type == "login_attempt" and event.data.get("success") is False
    ]
    if len(failed_logins) >= 4:
        evidence = tuple(
            DetectionEvidence(event.event_id, _timestamp(event.timestamp), "Nieudane logowanie")
            for event in failed_logins[:5]
        )
        detections.append(
            Detection(
                detection_id=f"{session_id}:credential_attack",
                category="credential_attack",
                severity="medium",
                confidence="high",
                score=48,
                title="Seria nieudanych logowań",
                summary=(
                    "W jednej sesji wystąpiły co najmniej cztery nieudane próby. "
                    "Pełne wykrywanie brute force między sesjami będzie osobną korelacją."
                ),
                evidence=evidence,
            )
        )

    return sorted(detections, key=lambda item: (-item.score, item.category))
