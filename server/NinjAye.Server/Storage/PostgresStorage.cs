using Npgsql;
using NpgsqlTypes;
using System.Text.Json;

namespace NinjAye.Server;

public sealed class PostgresStorage : IStorage
{
    private readonly string _connectionString;
    private string? _initializeSql;

    public PostgresStorage(string connectionString)
    {
        _connectionString = connectionString;
    }

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        _initializeSql ??= await File.ReadAllTextAsync(
            Path.Combine(
                AppContext.BaseDirectory,
                "database",
                "001_init.sql"),
            cancellationToken);

        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            _initializeSql,
            connection);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<InstallationIdentity> EnrollAsync(
        string installId,
        string machineLabel,
        byte[] tokenHash,
        CancellationToken cancellationToken)
    {
        const string sql =
            """
            INSERT INTO ninjaye_installations
                (id, install_id, machine_label, token_hash, created_at, last_seen_at)
            VALUES
                (@id, @install_id, @machine_label, @token_hash, now(), now())
            ON CONFLICT (install_id) DO UPDATE SET
                machine_label = EXCLUDED.machine_label,
                token_hash = EXCLUDED.token_hash,
                last_seen_at = now()
            RETURNING id, install_id;
            """;

        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection);
        command.Parameters.AddWithValue("id", Guid.NewGuid());
        command.Parameters.AddWithValue("install_id", installId);
        command.Parameters.AddWithValue("machine_label", machineLabel);
        command.Parameters.AddWithValue("token_hash", tokenHash);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);
        return new InstallationIdentity(
            reader.GetGuid(0),
            reader.GetString(1));
    }

    public async Task<InstallationIdentity?> AuthenticateAsync(
        byte[] tokenHash,
        CancellationToken cancellationToken)
    {
        const string sql =
            """
            SELECT id, install_id
            FROM ninjaye_installations
            WHERE token_hash = @token_hash AND disabled = false
            LIMIT 1;
            """;

        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection);
        command.Parameters.AddWithValue("token_hash", tokenHash);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
            return null;

        return new InstallationIdentity(
            reader.GetGuid(0),
            reader.GetString(1));
    }

    public async Task StartSessionAsync(
        InstallationIdentity installation,
        SessionStartRequest request,
        CancellationToken cancellationToken)
    {
        const string sql =
            """
            INSERT INTO ninjaye_sessions
                (id, installation_id, game_name, game_pid, game_path,
                 dll_path, server_id, dll_version, primary_client_id,
                 identities, started_at, last_heartbeat_at, last_status_at,
                 last_activity_at, metadata)
            VALUES
                (@id, @installation_id, @game_name, @game_pid, @game_path,
                 @dll_path, @server_id, @dll_version, @primary_client_id,
                 @identities, now(), now(), now(), now(), @metadata)
            ON CONFLICT (id) DO UPDATE SET
                game_name = CASE
                    WHEN EXCLUDED.game_name <> ''
                    THEN EXCLUDED.game_name
                    ELSE ninjaye_sessions.game_name
                END,
                game_pid = CASE
                    WHEN EXCLUDED.game_pid <> 0
                    THEN EXCLUDED.game_pid
                    ELSE ninjaye_sessions.game_pid
                END,
                game_path = CASE
                    WHEN EXCLUDED.game_path <> ''
                    THEN EXCLUDED.game_path
                    ELSE ninjaye_sessions.game_path
                END,
                dll_path = CASE
                    WHEN EXCLUDED.dll_path <> ''
                    THEN EXCLUDED.dll_path
                    ELSE ninjaye_sessions.dll_path
                END,
                server_id = CASE
                    WHEN EXCLUDED.server_id <> 0
                    THEN EXCLUDED.server_id
                    ELSE ninjaye_sessions.server_id
                END,
                dll_version = CASE
                    WHEN EXCLUDED.dll_version <> ''
                    THEN EXCLUDED.dll_version
                    ELSE ninjaye_sessions.dll_version
                END,
                primary_client_id = CASE
                    WHEN EXCLUDED.primary_client_id <> ''
                    THEN EXCLUDED.primary_client_id
                    ELSE ninjaye_sessions.primary_client_id
                END,
                identities = CASE
                    WHEN EXCLUDED.identities <> '{}'::jsonb
                    THEN EXCLUDED.identities
                    ELSE ninjaye_sessions.identities
                END,
                last_heartbeat_at = now(),
                last_status_at = now(),
                last_activity_at = now(),
                metadata = ninjaye_sessions.metadata || EXCLUDED.metadata
            WHERE ninjaye_sessions.installation_id =
                EXCLUDED.installation_id;
            """;

        await ExecuteAsync(
            sql,
            cancellationToken,
            ("id", request.SessionId),
            ("installation_id", installation.InstallationId),
            ("game_name", request.GameName),
            ("game_pid", (long)request.GameProcessId),
            ("game_path", request.GamePath),
            ("dll_path", request.DllPath),
            ("server_id", (long)request.ServerId),
            ("dll_version", request.DllVersion),
            ("primary_client_id", request.PrimaryClientId),
            ("identities", Jsonb("identities", request.Identities)),
            ("metadata", Jsonb("metadata", request.Metadata)));
    }

    public async Task<bool> HeartbeatAsync(
        InstallationIdentity installation,
        HeartbeatRequest request,
        CancellationToken cancellationToken)
    {
        const string sql =
            """
            UPDATE ninjaye_sessions SET
                game_pid = @game_pid,
                uptime_seconds = @uptime_seconds,
                detection_count = @detection_count,
                report_count = @report_count,
                last_heartbeat_at = now(),
                metadata = @metadata
            WHERE id = @session_id AND installation_id = @installation_id;
            """;

        return await ExecuteAsync(
            sql,
            cancellationToken,
            ("session_id", request.SessionId),
            ("installation_id", installation.InstallationId),
            ("game_pid", (long)request.GameProcessId),
            ("uptime_seconds", (long)request.UptimeSeconds),
            ("detection_count", (long)request.DetectionCount),
            ("report_count", (long)request.ReportCount),
            ("metadata", Jsonb("metadata", request.Metadata)));
    }

    public async Task<bool> SessionBelongsAsync(
        InstallationIdentity installation,
        Guid sessionId,
        CancellationToken cancellationToken)
    {
        const string sql =
            """
            SELECT EXISTS(
                SELECT 1
                FROM ninjaye_sessions
                WHERE id = @session_id AND installation_id = @installation_id);
            """;

        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection);
        command.Parameters.AddWithValue("session_id", sessionId);
        command.Parameters.AddWithValue(
            "installation_id",
            installation.InstallationId);
        return (bool)(await command.ExecuteScalarAsync(cancellationToken) ?? false);
    }

    public async Task<bool> RecordSessionActivityAsync(
        InstallationIdentity installation,
        SessionActivityRequest request,
        CancellationToken cancellationToken)
    {
        const string sql =
            """
            UPDATE ninjaye_sessions SET
                game_pid = CASE
                    WHEN @game_pid <> 0 THEN @game_pid
                    ELSE game_pid
                END,
                last_endpoint = @endpoint,
                last_heartbeat_at = now(),
                last_activity_at = now(),
                last_event_at = CASE
                    WHEN @event_increment > 0 THEN now()
                    ELSE last_event_at
                END,
                last_report_at = CASE
                    WHEN @report_increment > 0 THEN now()
                    ELSE last_report_at
                END,
                last_artifact_at = CASE
                    WHEN @artifact_increment > 0 THEN now()
                    ELSE last_artifact_at
                END,
                event_count = event_count + @event_increment,
                report_count = report_count + @report_increment,
                detection_count = detection_count + @detection_increment,
                artifact_count = artifact_count + @artifact_increment,
                metadata = metadata || jsonb_build_object(
                    'lastEndpoint', @endpoint,
                    'lastActivity', @data)
            WHERE id = @session_id
              AND installation_id = @installation_id;
            """;

        return await ExecuteAsync(
            sql,
            cancellationToken,
            ("session_id", request.SessionId),
            ("installation_id", installation.InstallationId),
            ("game_pid", (long)request.GameProcessId),
            ("endpoint", request.Endpoint),
            ("event_increment", request.EventIncrement),
            ("report_increment", request.ReportIncrement),
            ("detection_increment", request.DetectionIncrement),
            ("artifact_increment", request.ArtifactIncrement),
            ("data", Jsonb("data", request.Data)));
    }

    public async Task<long> InsertEventAsync(
        InstallationIdentity installation,
        EventRequest request,
        CancellationToken cancellationToken)
    {
        const string sql =
            """
            INSERT INTO ninjaye_events
                (installation_id, session_id, event_id, event_type, severity,
                 occurred_at, received_at, process_id, thread_id, data)
            VALUES
                (@installation_id, @session_id, @event_id, @event_type, @severity,
                 @occurred_at, now(), @process_id, @thread_id, @data)
            ON CONFLICT (installation_id, event_id) DO UPDATE SET
                event_type = EXCLUDED.event_type,
                severity = EXCLUDED.severity,
                occurred_at = EXCLUDED.occurred_at,
                received_at = now(),
                process_id = EXCLUDED.process_id,
                thread_id = EXCLUDED.thread_id,
                data = EXCLUDED.data
            RETURNING id;
            """;

        return await InsertReturningIdAsync(
            sql,
            cancellationToken,
            ("installation_id", installation.InstallationId),
            ("session_id", request.SessionId),
            ("event_id", request.EventId),
            ("event_type", request.Type),
            ("severity", request.Severity),
            ("occurred_at", request.OccurredAt),
            ("process_id", (long)request.ProcessId),
            ("thread_id", (long)request.ThreadId),
            ("data", Jsonb("data", request.Data)));
    }

    public async Task<long> InsertReportAsync(
        InstallationIdentity installation,
        ReportRequest request,
        CancellationToken cancellationToken)
    {
        const string sql =
            """
            INSERT INTO ninjaye_reports
                (installation_id, session_id, report_id, created_at, received_at,
                 client, process, telemetry)
            VALUES
                (@installation_id, @session_id, @report_id, @created_at, now(),
                 @client, @process, @telemetry)
            ON CONFLICT (installation_id, report_id) DO UPDATE SET
                created_at = EXCLUDED.created_at,
                received_at = now(),
                client = EXCLUDED.client,
                process = EXCLUDED.process,
                telemetry = EXCLUDED.telemetry
            RETURNING id;
            """;

        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("installation_id", installation.InstallationId);
        command.Parameters.AddWithValue("session_id", request.SessionId);
        command.Parameters.AddWithValue("report_id", request.ReportId);
        command.Parameters.AddWithValue("created_at", request.CreatedAt);
        command.Parameters.Add(Jsonb("client", request.Client));
        command.Parameters.Add(Jsonb("process", request.Process));
        command.Parameters.Add(Jsonb("telemetry", request.Telemetry));
        var reportId = (long)(await command.ExecuteScalarAsync(cancellationToken)
            ?? throw new InvalidOperationException("Report insert returned no id."));

        await using (var clearCommand = new NpgsqlCommand(
            "DELETE FROM ninjaye_detections WHERE report_id = @report_id;",
            connection,
            transaction))
        {
            clearCommand.Parameters.AddWithValue("report_id", reportId);
            await clearCommand.ExecuteNonQueryAsync(cancellationToken);
        }

        foreach (var detection in request.Detections)
        {
            await using var detectionCommand = new NpgsqlCommand(
                """
                INSERT INTO ninjaye_detections
                    (installation_id, session_id, report_id, code, severity,
                     confidence, detected_at, details)
                VALUES
                    (@installation_id, @session_id, @report_id, @code, @severity,
                     @confidence, @detected_at, @details);
                """,
                connection,
                transaction);
            detectionCommand.Parameters.AddWithValue(
                "installation_id",
                installation.InstallationId);
            detectionCommand.Parameters.AddWithValue("session_id", request.SessionId);
            detectionCommand.Parameters.AddWithValue("report_id", reportId);
            detectionCommand.Parameters.AddWithValue(
                "code",
                DetectionCodeMap.Resolve(detection.CodeId));
            detectionCommand.Parameters.AddWithValue("severity", detection.Severity);
            detectionCommand.Parameters.AddWithValue(
                "confidence",
                detection.Confidence);
            detectionCommand.Parameters.AddWithValue(
                "detected_at",
                detection.DetectedAt);
            detectionCommand.Parameters.Add(
                Jsonb("details", detection.Details));
            await detectionCommand.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return reportId;
    }

    public async Task<long> InsertArtifactAsync(
        InstallationIdentity installation,
        ArtifactRequest request,
        CancellationToken cancellationToken)
    {
        const string sql =
            """
            INSERT INTO ninjaye_artifacts
                (installation_id, session_id, artifact_id, kind, name, sha256,
                 size_bytes, observed_at, received_at, metadata, content)
            VALUES
                (@installation_id, @session_id, @artifact_id, @kind, @name,
                 @sha256, @size_bytes, @observed_at, now(), @metadata,
                 @content)
            ON CONFLICT (installation_id, artifact_id) DO UPDATE SET
                kind = EXCLUDED.kind,
                name = EXCLUDED.name,
                sha256 = EXCLUDED.sha256,
                size_bytes = EXCLUDED.size_bytes,
                observed_at = EXCLUDED.observed_at,
                received_at = now(),
                metadata = EXCLUDED.metadata,
                content = EXCLUDED.content
            RETURNING id;
            """;

        return await InsertReturningIdAsync(
            sql,
            cancellationToken,
            ("installation_id", installation.InstallationId),
            ("session_id", request.SessionId),
            ("artifact_id", request.ArtifactId),
            ("kind", request.Kind),
            ("name", request.Name),
            ("sha256", request.Sha256),
            ("size_bytes", request.Size),
            ("observed_at", request.ObservedAt),
            ("metadata", Jsonb("metadata", request.Metadata)),
            ("content", request.Content));
    }

    public async Task<StoredSummary> GetSummaryAsync(
        CancellationToken cancellationToken)
    {
        const string sql =
            """
            SELECT
                (SELECT count(*) FROM ninjaye_installations),
                (SELECT count(*) FROM ninjaye_sessions),
                (SELECT count(*) FROM ninjaye_events),
                (SELECT count(*) FROM ninjaye_reports),
                (SELECT count(*) FROM ninjaye_detections),
                (SELECT count(*) FROM ninjaye_artifacts);
            """;

        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);
        return new StoredSummary(
            reader.GetInt64(0),
            reader.GetInt64(1),
            reader.GetInt64(2),
            reader.GetInt64(3),
            reader.GetInt64(4),
            reader.GetInt64(5));
    }

    private async Task<bool> ExecuteAsync(
        string sql,
        CancellationToken cancellationToken,
        params (string Name, object Value)[] parameters)
    {
        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

    private async Task<long> InsertReturningIdAsync(
        string sql,
        CancellationToken cancellationToken,
        params (string Name, object Value)[] parameters)
    {
        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        return (long)(await command.ExecuteScalarAsync(cancellationToken)
            ?? throw new InvalidOperationException("Insert returned no id."));
    }

    private static void AddParameters(
        NpgsqlCommand command,
        params (string Name, object Value)[] parameters)
    {
        foreach (var parameter in parameters)
        {
            if (parameter.Value is NpgsqlParameter npgsqlParameter)
            {
                npgsqlParameter.ParameterName = parameter.Name;
                command.Parameters.Add(npgsqlParameter);
            }
            else
            {
                command.Parameters.AddWithValue(parameter.Name, parameter.Value);
            }
        }
    }

    private static NpgsqlParameter Jsonb(
        string name,
        JsonElement value)
    {
        return new NpgsqlParameter
        {
            ParameterName = name,
            NpgsqlDbType = NpgsqlDbType.Jsonb,
            Value = value.GetRawText(),
        };
    }
}
