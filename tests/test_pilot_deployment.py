from pathlib import Path

ROOT = Path(__file__).parents[1]
PILOT = ROOT / "deploy" / "pilot"


def test_sensor_binding_is_fail_closed_by_default() -> None:
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    environment = (ROOT / ".env.example").read_text(encoding="utf-8")
    gateway = compose.split("\n  ssh-gateway:", maxsplit=1)[1].split(
        "\nnetworks:", maxsplit=1
    )[0]

    assert "${SENSOR_BIND_IP:-127.0.0.1}" in compose
    assert compose.count("${SENSOR_ID:") == 2
    assert "SENSOR_BIND_IP=127.0.0.1" in environment
    assert "PUBLICATION_APPROVED=no" in environment
    assert "      - sensor-lab" in gateway
    assert "      - sensor-ingress" in gateway
    assert "      - ingress\n" not in gateway
    assert "172.30.255.0/28" in compose


def test_kill_switch_preserves_evidence_and_closes_firewall_first() -> None:
    script = (PILOT / "honeynet-kill-switch").read_text(encoding="utf-8")

    close_position = script.index('"${FIREWALL_GATE}" close')
    stop_position = script.index("stop --timeout 3 ssh-gateway")
    assert close_position < stop_position
    for destructive in ("down -v", "rm -v", "volume rm", "system prune"):
        assert destructive not in script


def test_monitor_failure_triggers_kill_switch() -> None:
    monitor = (PILOT / "honeynet-monitor").read_text(encoding="utf-8")
    unit = (PILOT / "systemd" / "honeynet-monitor.service").read_text(encoding="utf-8")

    assert "collector-health" in monitor
    assert "127.0.0.1:8000/health" in monitor
    assert 'fail "${label} has unexpected network attachments"' in monitor
    assert "require_sensor_networks cowrie Cowrie 1 sensor-lab" in monitor
    assert (
        'require_sensor_networks ssh-gateway "SSH gateway" 2 sensor-lab sensor-ingress'
        in monitor
    )
    assert '"${BASELINE}" verify' in monitor
    assert "docker stats --no-stream" in monitor
    assert 'CPU_BREACH_COUNT_LIMIT="${HONEYPOT_CPU_BREACH_COUNT_LIMIT:-3}"' in monitor
    assert "consecutive check" in monitor
    assert "cpu_breach_count >= CPU_BREACH_COUNT_LIMIT" in monitor
    assert 'mv -f "${cpu_state_temporary}" "${CPU_STATE_FILE}"' in monitor
    assert 'QUARANTINE_LIMIT_BYTES="${HONEYPOT_QUARANTINE_LIMIT_BYTES:-2147483648}"' in monitor
    assert 'QUARANTINE_WARN_PERCENT="${HONEYPOT_QUARANTINE_WARN_PERCENT:-70}"' in monitor
    assert "quarantine_bytes >= quarantine_warn_bytes" in monitor
    assert 'fail "quarantine size ${quarantine_bytes} bytes reached limit ${QUARANTINE_LIMIT_BYTES}"' in monitor
    assert "COWRIE_HONEYPOT_DOWNLOAD_LIMIT_SIZE" in monitor
    assert "OnFailure=honeynet-kill-switch.service" in unit


def test_cowrie_capture_and_quarantine_limits_are_bounded() -> None:
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    environment = (ROOT / ".env.example").read_text(encoding="utf-8")
    preflight = (PILOT / "honeynet-preflight").read_text(encoding="utf-8")

    assert (
        "COWRIE_HONEYPOT_DOWNLOAD_LIMIT_SIZE: "
        "${COWRIE_DOWNLOAD_LIMIT_SIZE_BYTES:-16777216}"
    ) in compose
    assert "COWRIE_DOWNLOAD_LIMIT_SIZE_BYTES=16777216" in environment
    assert "HONEYPOT_QUARANTINE_LIMIT_BYTES=2147483648" in environment
    assert "HONEYPOT_QUARANTINE_WARN_PERCENT=70" in environment
    assert "capture limit must be between 1 MiB and 64 MiB" in preflight
    assert "quarantine limit must be between 128 MiB and 16 GiB" in preflight
    assert "quarantine limit must exceed the single-sample capture limit" in preflight


def test_cowrie_uses_consistent_persona_and_no_network_transfer_override() -> None:
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    cowrie = compose.split("\n  cowrie:", maxsplit=1)[1].split(
        "\n  ssh-gateway:", maxsplit=1
    )[0]

    assert "COWRIE_HONEYPOT_HOSTNAME: app-prod-01" in cowrie
    assert "COWRIE_HONEYPOT_CONTENTS_PATH:" in cowrie
    assert "COWRIE_SHELL_KERNEL_VERSION: 6.1.0-21-amd64" in cowrie
    assert "COWRIE_SSH_VERSION: SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3" in cowrie
    assert "cowrie-persona/commands/safe_transfer.py" in cowrie
    assert "cowrie-persona/safe-placeholder.sh" in cowrie
    assert "sensor-lab" in cowrie
    assert "sensor-ingress" not in cowrie


def test_public_activation_requires_explicit_approval_and_address() -> None:
    script = (PILOT / "honeynet-sensor-open").read_text(encoding="utf-8")

    assert '"${PUBLICATION_APPROVED:-no}" == "yes"' in script
    assert '"${SENSOR_BIND_IP}" != "127.0.0.1"' in script
    assert '"${SENSOR_BIND_IP}" != "0.0.0.0"' in script
    assert script.index('"${FIREWALL_GATE}" close') < script.index(
        '"${FIREWALL_GATE}" open'
    )
    assert 'trap cleanup_on_exit EXIT' in script
    assert '"${PREFLIGHT}"' in script


def test_preflight_is_read_only_and_rejects_unsupported_firewall() -> None:
    script = (PILOT / "honeynet-preflight").read_text(encoding="utf-8")

    assert "PUBLICATION_APPROVED" in script
    assert "POSTGRES_PASSWORD" in script
    assert "REPORT_PSEUDONYM_KEY" in script
    assert "GRAFANA_DB_PASSWORD" in script
    assert "GRAFANA_ADMIN_PASSWORD" in script
    assert "DOCKER-USER unavailable" in script
    assert "config --quiet" in script
    assert "PORT == 22" in script
    assert "PORT >= 1024" in script
    for mutation in ("iptables -I", "iptables -A", "iptables -F", "docker compose up"):
        assert mutation not in script


def test_firewall_blocks_new_gateway_egress_before_sensor_gate() -> None:
    script = (PILOT / "honeynet-firewall-gate").read_text(encoding="utf-8")

    assert 'INGRESS_SUBNET="172.30.255.0/28"' in script
    assert "honeynet-sensor-egress" in script
    assert "--ctstate NEW" in script
    assert "-j DROP" in script
    assert script.index("ensure_egress_block") < script.index('iptables -w 5 -N "${CHAIN}"')
    assert 'sensor gate is not attached to original TCP port ${PORT}' in script
    status_section = script.split("  status)", maxsplit=1)[1]
    assert '--ctorigdstport "${PORT}"' in status_section


def test_baseline_excludes_secrets_and_tracks_images() -> None:
    script = (PILOT / "honeynet-baseline").read_text(encoding="utf-8")

    assert '"${PROJECT_DIR}/.env"' not in script.split("render_baseline()", maxsplit=1)[1]
    assert "sha256sum" in script
    assert "IMAGE  %s  %s" in script
    assert "PUBLICATION_APPROVED" in script
    assert '"${PROJECT_DIR}/deploy/cowrie-persona"' in script
