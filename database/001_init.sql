CREATE TABLE IF NOT EXISTS ninjaye_installations
(
    id uuid PRIMARY KEY,
    install_id text NOT NULL UNIQUE,
    machine_label text NOT NULL DEFAULT '',
    token_hash bytea NOT NULL,
    disabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_ninjaye_installations_token_hash
    ON ninjaye_installations (token_hash);

CREATE TABLE IF NOT EXISTS ninjaye_sessions
(
    id uuid PRIMARY KEY,
    installation_id uuid NOT NULL
        REFERENCES ninjaye_installations(id) ON DELETE CASCADE,
    game_name text NOT NULL,
    game_pid bigint NOT NULL,
    game_path text NOT NULL DEFAULT '',
    dll_path text NOT NULL DEFAULT '',
    server_id bigint NOT NULL DEFAULT 0,
    dll_version text NOT NULL DEFAULT '',
    primary_client_id text NOT NULL DEFAULT '',
    identities jsonb NOT NULL DEFAULT '{}'::jsonb,
    started_at timestamptz NOT NULL,
    last_heartbeat_at timestamptz NOT NULL,
    last_status_at timestamptz,
    last_event_at timestamptz,
    last_report_at timestamptz,
    last_artifact_at timestamptz,
    last_activity_at timestamptz,
    uptime_seconds bigint NOT NULL DEFAULT 0,
    event_count bigint NOT NULL DEFAULT 0,
    detection_count bigint NOT NULL DEFAULT 0,
    report_count bigint NOT NULL DEFAULT 0,
    artifact_count bigint NOT NULL DEFAULT 0,
    last_endpoint text NOT NULL DEFAULT '',
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

ALTER TABLE ninjaye_sessions
    ADD COLUMN IF NOT EXISTS server_id bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS dll_version text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS primary_client_id text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS identities jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS last_status_at timestamptz,
    ADD COLUMN IF NOT EXISTS last_event_at timestamptz,
    ADD COLUMN IF NOT EXISTS last_report_at timestamptz,
    ADD COLUMN IF NOT EXISTS last_artifact_at timestamptz,
    ADD COLUMN IF NOT EXISTS last_activity_at timestamptz,
    ADD COLUMN IF NOT EXISTS event_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS artifact_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_endpoint text NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS ix_ninjaye_sessions_installation
    ON ninjaye_sessions (installation_id, started_at DESC);

CREATE INDEX IF NOT EXISTS ix_ninjaye_sessions_server
    ON ninjaye_sessions (server_id, started_at DESC);

CREATE INDEX IF NOT EXISTS ix_ninjaye_sessions_identities_gin
    ON ninjaye_sessions USING gin (identities);

CREATE INDEX IF NOT EXISTS ix_ninjaye_sessions_metadata_gin
    ON ninjaye_sessions USING gin (metadata);

CREATE TABLE IF NOT EXISTS ninjaye_events
(
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    installation_id uuid NOT NULL
        REFERENCES ninjaye_installations(id) ON DELETE CASCADE,
    session_id uuid NOT NULL
        REFERENCES ninjaye_sessions(id) ON DELETE CASCADE,
    event_id text NOT NULL,
    event_type text NOT NULL,
    severity integer NOT NULL,
    occurred_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL,
    process_id bigint NOT NULL DEFAULT 0,
    thread_id bigint NOT NULL DEFAULT 0,
    data jsonb NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (installation_id, event_id)
);

CREATE INDEX IF NOT EXISTS ix_ninjaye_events_session_time
    ON ninjaye_events (session_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS ix_ninjaye_events_data_gin
    ON ninjaye_events USING gin (data);

CREATE TABLE IF NOT EXISTS ninjaye_reports
(
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    installation_id uuid NOT NULL
        REFERENCES ninjaye_installations(id) ON DELETE CASCADE,
    session_id uuid NOT NULL
        REFERENCES ninjaye_sessions(id) ON DELETE CASCADE,
    report_id text NOT NULL,
    created_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL,
    client jsonb NOT NULL DEFAULT '{}'::jsonb,
    process jsonb NOT NULL DEFAULT '{}'::jsonb,
    telemetry jsonb NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (installation_id, report_id)
);

CREATE INDEX IF NOT EXISTS ix_ninjaye_reports_session_time
    ON ninjaye_reports (session_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ix_ninjaye_reports_client_gin
    ON ninjaye_reports USING gin (client);

CREATE INDEX IF NOT EXISTS ix_ninjaye_reports_process_gin
    ON ninjaye_reports USING gin (process);

CREATE INDEX IF NOT EXISTS ix_ninjaye_reports_telemetry_gin
    ON ninjaye_reports USING gin (telemetry);

CREATE TABLE IF NOT EXISTS ninjaye_detections
(
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    installation_id uuid NOT NULL
        REFERENCES ninjaye_installations(id) ON DELETE CASCADE,
    session_id uuid NOT NULL
        REFERENCES ninjaye_sessions(id) ON DELETE CASCADE,
    report_id bigint NOT NULL
        REFERENCES ninjaye_reports(id) ON DELETE CASCADE,
    code text NOT NULL,
    severity integer NOT NULL,
    confidence integer NOT NULL,
    detected_at timestamptz NOT NULL,
    details jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS ix_ninjaye_detections_code_time
    ON ninjaye_detections (code, detected_at DESC);

CREATE INDEX IF NOT EXISTS ix_ninjaye_detections_details_gin
    ON ninjaye_detections USING gin (details);

CREATE TABLE IF NOT EXISTS ninjaye_artifacts
(
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    installation_id uuid NOT NULL
        REFERENCES ninjaye_installations(id) ON DELETE CASCADE,
    session_id uuid NOT NULL
        REFERENCES ninjaye_sessions(id) ON DELETE CASCADE,
    artifact_id text NOT NULL,
    kind text NOT NULL,
    name text NOT NULL,
    sha256 text NOT NULL,
    size_bytes bigint NOT NULL,
    observed_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    content bytea NOT NULL,
    UNIQUE (installation_id, artifact_id)
);

CREATE INDEX IF NOT EXISTS ix_ninjaye_artifacts_sha256
    ON ninjaye_artifacts (sha256);

CREATE INDEX IF NOT EXISTS ix_ninjaye_artifacts_metadata_gin
    ON ninjaye_artifacts USING gin (metadata);

ALTER TABLE ninjaye_artifacts
    ADD COLUMN IF NOT EXISTS content bytea NOT NULL DEFAULT ''::bytea;
