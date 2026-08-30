#!/usr/bin/env sh
set -eu

: "${POSTGRES_HOST:=db}"
: "${POSTGRES_DB:=honeynet}"
: "${POSTGRES_USER:=honeynet}"
: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
: "${GRAFANA_DB_PASSWORD:?GRAFANA_DB_PASSWORD is required}"

export PGPASSWORD="${POSTGRES_PASSWORD}"

psql \
  --host "${POSTGRES_HOST}" \
  --username "${POSTGRES_USER}" \
  --dbname "${POSTGRES_DB}" \
  --set ON_ERROR_STOP=1 \
  --set grafana_password="${GRAFANA_DB_PASSWORD}" <<'SQL'
SELECT format('CREATE ROLE grafana_reader LOGIN PASSWORD %L', :'grafana_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'grafana_reader')
\gexec

SELECT format('ALTER ROLE grafana_reader PASSWORD %L', :'grafana_password')
\gexec

ALTER ROLE grafana_reader NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;

CREATE SCHEMA IF NOT EXISTS grafana_safe AUTHORIZATION honeynet;

CREATE OR REPLACE VIEW grafana_safe.session_event_facts
WITH (security_barrier = true)
AS
SELECT
    event_id,
    "timestamp" AS observed_at,
    sensor_id,
    session_id,
    event_type,
    CASE
        WHEN event_type <> 'artifact_captured' THEN false
        WHEN lower(coalesce(data->>'sha256', '')) =
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            THEN true
        WHEN coalesce(data->>'capture_status', '') IN ('empty_upload', 'incomplete_transfer')
            THEN true
        WHEN coalesce(data->>'size_bytes', '') = '0' THEN true
        ELSE false
    END AS incomplete_artifact
FROM public.events;

CREATE OR REPLACE VIEW grafana_safe.event_stream
WITH (security_barrier = true)
AS
SELECT
    event_id,
    "timestamp" AS observed_at,
    sensor_id,
    session_id,
    event_type
FROM grafana_safe.session_event_facts;

CREATE OR REPLACE VIEW grafana_safe.session_summary
WITH (security_barrier = true)
AS
WITH session_facts AS (
    SELECT
        session_id,
        min(sensor_id) AS sensor_id,
        min(observed_at) AS started_at,
        max(observed_at) AS ended_at,
        count(*)::bigint AS event_count,
        count(*) FILTER (WHERE event_type = 'command_input')::bigint AS command_count,
        count(*) FILTER (WHERE event_type = 'login_attempt')::bigint AS login_count,
        count(*) FILTER (
            WHERE event_type IN ('artifact_captured', 'file_download_requested')
        )::bigint
            AS artifact_count,
        bool_or(event_type = 'artifact_captured' AND NOT incomplete_artifact)
            AS has_captured_artifact,
        bool_or(event_type = 'artifact_captured' AND incomplete_artifact) AS has_empty_upload,
        bool_or(event_type = 'file_download_requested') AS has_transfer,
        bool_or(event_type = 'command_input') AS has_command,
        bool_or(event_type = 'login_attempt') AS has_login
    FROM grafana_safe.session_event_facts
    GROUP BY session_id
)
SELECT
    session_id,
    sensor_id,
    started_at,
    ended_at,
    extract(epoch FROM ended_at - started_at)::bigint AS duration_seconds,
    event_count,
    command_count,
    login_count,
    artifact_count,
    CASE
        WHEN has_captured_artifact THEN 92
        WHEN has_transfer THEN 74
        WHEN has_empty_upload THEN 18
        WHEN has_command THEN 58
        WHEN has_login THEN 28
        ELSE 12
    END::integer AS risk_score,
    CASE
        WHEN has_captured_artifact THEN 'Artefakt przechwycony'
        WHEN has_transfer THEN 'Próba dostarczenia pliku'
        WHEN has_empty_upload THEN 'Pusty lub niedokończony upload'
        WHEN has_command THEN 'Aktywna sesja poleceń'
        WHEN has_login THEN 'Próba uwierzytelnienia'
        ELSE 'Obserwacja sieciowa'
    END AS risk_label
FROM session_facts;

REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM grafana_reader;
REVOKE ALL PRIVILEGES ON public.events FROM grafana_reader;
REVOKE ALL PRIVILEGES ON grafana_safe.session_event_facts FROM grafana_reader;
REVOKE CREATE ON SCHEMA public FROM grafana_reader;
GRANT CONNECT ON DATABASE honeynet TO grafana_reader;
GRANT USAGE ON SCHEMA grafana_safe TO grafana_reader;
GRANT SELECT ON grafana_safe.event_stream, grafana_safe.session_summary TO grafana_reader;

ALTER DEFAULT PRIVILEGES IN SCHEMA grafana_safe REVOKE ALL ON TABLES FROM grafana_reader;
SQL

printf 'Grafana safe projection is ready.\n'
