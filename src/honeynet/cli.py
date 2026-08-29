import argparse
import json
import time
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError

from honeynet.collector import CollectorResult, CowrieFileCollector
from honeynet.config import get_settings
from honeynet.cowrie import normalize_lines
from honeynet.database import SessionLocal, create_schema
from honeynet.health import check_collector_state
from honeynet.models import Event
from honeynet.reporting import render_session_report
from honeynet.repository import EventRepository
from honeynet.retention import PILOT_MAX_RETENTION_DAYS, RetentionResult, apply_retention


def import_jsonl(path: Path) -> tuple[int, int]:
    events: list[Event] = []
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                events.append(Event.model_validate_json(line))
            except (ValidationError, json.JSONDecodeError) as exc:
                raise ValueError(f"Niepoprawny rekord w linii {line_number}: {exc}") from exc

    create_schema()
    with SessionLocal() as session:
        return EventRepository(session).add_many(events)


def import_cowrie(path: Path) -> tuple[int, int]:
    with path.open("r", encoding="utf-8") as stream:
        events = list(normalize_lines(stream))
    create_schema()
    with SessionLocal() as session:
        return EventRepository(session).add_many(events)


def write_report(session_id: str, output: Path) -> None:
    create_schema()
    with SessionLocal() as session:
        events = EventRepository(session).session_events(session_id)
    report = render_session_report(events, get_settings().report_pseudonym_key)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")


def run_retention(
    days: int, execute: bool, *, now: datetime | None = None
) -> RetentionResult:
    create_schema()
    with SessionLocal() as session:
        return apply_retention(
            EventRepository(session),
            days=days,
            execute=execute,
            now=now,
        )


def _retention_message(result: RetentionResult, *, execute: bool) -> str:
    mode = "WYKONANO" if execute else "PODGLĄD"
    return (
        f"{mode}: granica={result.cutoff.isoformat()} "
        f"kwalifikuje={result.eligible} usunięto={result.deleted}"
    )


def retention_worker(days: int, interval: float) -> None:
    """Apply pilot retention immediately and then at a fixed interval."""

    try:
        while True:
            print(_retention_message(run_retention(days, True), execute=True), flush=True)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("Proces retencji zatrzymany")


def _collector_message(result: CollectorResult) -> str:
    if result.waiting_for_file:
        return "Oczekiwanie na plik Cowrie"
    return (
        f"linie={result.lines_read} nowe={result.events_inserted} "
        f"duplikaty={result.duplicates} pominięte={result.ignored} błędy={result.errors}"
    )


def watch_cowrie(path: Path, state_path: Path, interval: float, once: bool) -> None:
    create_schema()
    collector = CowrieFileCollector(path, state_path, SessionLocal)
    previous_waiting_state: bool | None = None
    try:
        while True:
            result = collector.poll_once()
            has_activity = result.lines_read > 0 or result.errors > 0
            waiting_state_changed = result.waiting_for_file != previous_waiting_state
            if once or has_activity or waiting_state_changed:
                print(_collector_message(result), flush=True)
            previous_waiting_state = result.waiting_for_file
            if once:
                return
            time.sleep(interval)
    except KeyboardInterrupt:
        print("Collector zatrzymany")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="honeynet")
    commands = root.add_subparsers(dest="command", required=True)

    import_command = commands.add_parser("import", help="Importuj ustandaryzowany plik JSONL")
    import_command.add_argument("path", type=Path)

    cowrie_command = commands.add_parser("import-cowrie", help="Normalizuj i importuj JSONL Cowrie")
    cowrie_command.add_argument("path", type=Path)

    watch_command = commands.add_parser(
        "watch-cowrie", help="Śledź dopisywane rekordy Cowrie z trwałym kursorem"
    )
    watch_command.add_argument("path", type=Path)
    watch_command.add_argument("--state", type=Path, required=True)
    watch_command.add_argument("--interval", type=float, default=2.0)
    watch_command.add_argument("--once", action="store_true")

    report_command = commands.add_parser("report", help="Wygeneruj raport Markdown sesji")
    report_command.add_argument("session_id")
    report_command.add_argument("--output", type=Path, required=True)

    retention_command = commands.add_parser(
        "retention", help="Pokaż lub usuń zdarzenia starsze niż okres retencji"
    )
    retention_command.add_argument(
        "--days",
        type=int,
        default=PILOT_MAX_RETENTION_DAYS,
        help=f"Okres 1-{PILOT_MAX_RETENTION_DAYS} dni (domyślnie 30)",
    )
    retention_command.add_argument(
        "--execute",
        action="store_true",
        help="Wykonaj usunięcie; bez tej flagi działa wyłącznie podgląd",
    )

    retention_worker_command = commands.add_parser(
        "retention-worker", help="Cyklicznie wykonuj retencję danych pilota"
    )
    retention_worker_command.add_argument(
        "--days", type=int, default=PILOT_MAX_RETENTION_DAYS
    )
    retention_worker_command.add_argument("--interval", type=float, default=86_400)

    collector_health_command = commands.add_parser(
        "collector-health", help="Sprawdź świeżość heartbeat kolektora"
    )
    collector_health_command.add_argument("state", type=Path)
    collector_health_command.add_argument("--max-age", type=float, default=30.0)
    return root


def main() -> None:
    args = parser().parse_args()
    if args.command == "import":
        inserted, duplicates = import_jsonl(args.path)
        print(f"Zaimportowano: {inserted}; duplikaty: {duplicates}")
    elif args.command == "import-cowrie":
        inserted, duplicates = import_cowrie(args.path)
        print(f"Zaimportowano z Cowrie: {inserted}; duplikaty: {duplicates}")
    elif args.command == "watch-cowrie":
        if args.interval <= 0:
            raise SystemExit("--interval musi być większy od zera")
        watch_cowrie(args.path, args.state, args.interval, args.once)
    elif args.command == "report":
        write_report(args.session_id, args.output)
        print(f"Raport zapisany: {args.output}")
    elif args.command == "retention":
        try:
            result = run_retention(args.days, args.execute)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        print(_retention_message(result, execute=args.execute))
    elif args.command == "retention-worker":
        if args.interval < 60:
            raise SystemExit("--interval nie może być krótszy niż 60 sekund")
        try:
            retention_worker(args.days, args.interval)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    elif args.command == "collector-health":
        try:
            result = check_collector_state(args.state, max_age_seconds=args.max_age)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        age = "brak" if result.age_seconds is None else f"{result.age_seconds:.1f}s"
        print(f"collector={result.status} age={age}")
        if not result.healthy:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
