import hashlib
import hmac
import json
from collections import Counter
from datetime import UTC

from honeynet.database import StoredEvent


def as_utc(value):
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def pseudonymize_ip(ip: str, key: str) -> str:
    digest = hmac.new(key.encode(), ip.encode(), hashlib.sha256).hexdigest()[:12]
    return f"source-{digest}"


def _safe_detail(event: StoredEvent) -> str:
    allowed = {
        "success",
        "command",
        "url",
        "sha256",
        "filename",
        "reason",
    }
    detail = {key: value for key, value in event.data.items() if key in allowed}
    return json.dumps(detail, ensure_ascii=False, sort_keys=True) if detail else "—"


def render_session_report(events: list[StoredEvent], pseudonym_key: str) -> str:
    if not events:
        raise ValueError("Nie znaleziono zdarzeń dla sesji")

    first = events[0]
    counts = Counter(event.event_type for event in events)
    source = pseudonymize_ip(first.source_ip, pseudonym_key)
    generated_at = as_utc(first.timestamp).isoformat()

    lines = [
        f"# Raport sesji {first.session_id}",
        "",
        "> Raport defensywny. Źródłowy adres IP został pseudonimizowany.",
        "",
        "## Podsumowanie",
        "",
        f"- Sensor: `{first.sensor_id}`",
        f"- Źródło: `{source}`",
        f"- Początek obserwacji: `{generated_at}`",
        f"- Liczba zdarzeń: **{len(events)}**",
        "- Typy: " + ", ".join(f"`{name}` × {count}" for name, count in sorted(counts.items())),
        "",
        "## Oś czasu",
        "",
        "| Czas UTC | Typ | Szczegóły |",
        "|---|---|---|",
    ]
    for event in events:
        timestamp = as_utc(event.timestamp).isoformat()
        detail = _safe_detail(event).replace("|", "\\|").replace("\n", " ")
        lines.append(f"| `{timestamp}` | `{event.event_type}` | `{detail}` |")

    lines.extend(
        [
            "",
            "## Ograniczenia",
            "",
            (
                "Pojedyncza sesja nie dowodzi ukierunkowania ataku na Polskę ani "
                "atrybucji sprawcy. Może pochodzić z automatycznego skanowania Internetu."
            ),
            "",
        ]
    )
    return "\n".join(lines)
