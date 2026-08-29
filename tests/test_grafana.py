import json
from pathlib import Path

ROOT = Path(__file__).parents[1]
GRAFANA = ROOT / "deploy" / "grafana"


def test_grafana_dashboard_is_valid_and_contains_ready_panels() -> None:
    dashboard = json.loads(
        (GRAFANA / "dashboards" / "honeynet-overview.json").read_text(encoding="utf-8")
    )

    assert dashboard["uid"] == "pl-honeynet-overview"
    assert dashboard["refresh"] == "30s"
    panel_types = {panel["type"] for panel in dashboard["panels"]}
    assert {"nodeGraph", "stat", "table", "timeseries", "piechart"} <= panel_types


def test_grafana_projection_never_exposes_raw_evidence_columns() -> None:
    bootstrap = (GRAFANA / "bootstrap.sh").read_text(encoding="utf-8")
    event_view = bootstrap.split("CREATE OR REPLACE VIEW grafana_safe.event_stream", 1)[1]
    event_view = event_view.split("CREATE OR REPLACE VIEW grafana_safe.session_summary", 1)[0]

    for forbidden in (
        "source_ip",
        "source_port",
        "destination_port",
        "source_event",
        "data->",
        "password",
        "command",
        "url",
    ):
        assert forbidden not in event_view.lower()

    assert "REVOKE ALL PRIVILEGES ON public.events FROM grafana_reader" in bootstrap
    assert "GRANT SELECT ON grafana_safe.event_stream" in bootstrap


def test_grafana_is_loopback_only_and_uses_a_dedicated_reader() -> None:
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    datasource = (
        GRAFANA / "provisioning" / "datasources" / "honeynet.yaml"
    ).read_text(encoding="utf-8")
    service = compose.split("\n  grafana:", 1)[1].split("\n  cowrie:", 1)[0]

    assert '"127.0.0.1:${GRAFANA_PORT:-3000}:3000"' in service
    assert "GRAFANA_DB_PASSWORD" in service
    assert "user: grafana_reader" in datasource
    assert "password: $__env{GRAFANA_DB_PASSWORD}" in datasource
    assert "user: honeynet" not in datasource
    assert "GF_AUTH_ANONYMOUS_ENABLED: \"false\"" in service
    assert "GRAFANA_ROOT_URL" in service


def test_grafana_dashboard_queries_only_safe_schema() -> None:
    dashboard = (GRAFANA / "dashboards" / "honeynet-overview.json").read_text(
        encoding="utf-8"
    )

    assert "grafana_safe.event_stream" in dashboard
    assert "grafana_safe.session_summary" in dashboard
    assert "public.events" not in dashboard
    assert "source_ip" not in dashboard


def test_node_graph_is_aggregated_instead_of_drawing_every_session() -> None:
    dashboard = json.loads(
        (GRAFANA / "dashboards" / "honeynet-overview.json").read_text(
            encoding="utf-8"
        )
    )
    graph = next(panel for panel in dashboard["panels"] if panel["type"] == "nodeGraph")
    graph_sql = "\n".join(target["rawSql"] for target in graph["targets"])

    assert "behavior_groups" in graph_sql
    assert "'behavior:' || event_type" in graph_sql
    assert "'sensor-behavior:' || event_type" in graph_sql
    assert "'risk:'" not in graph_sql
    assert "'session:' || session_id" not in graph_sql
    assert "LIMIT 30" not in graph_sql


def test_vps_deployment_is_fail_closed_and_verifies_reader_isolation() -> None:
    script = (ROOT / "work" / "deploy-grafana-20260828.sh").read_text(encoding="utf-8")

    close_position = script.index('sudo "${GATE}" close')
    install_position = script.index('sudo install -m 0644 "${STAGING}/compose.yaml"')
    open_position = script.index("sudo systemctl start honeynet-sensor-open.service")
    assert close_position < install_position < open_position
    assert "SELECT source_ip FROM public.events" in script
    assert "konto Grafany ma niedozwolony dostęp" in script
    assert "127.0.0.1:*)" in script
    assert "GRAFANA_ROOT_URL=http://127.0.0.1:13000" in script
    assert 'sudo test -x "${GATE}"' in script
    assert "GRAFANA_ADMIN_PASSWORD" not in script.split("printf '\\nGRAFANA_DEPLOYMENT_OK", 1)[1]
