# PostgreSQL schema

Schema source:

```text
database/001_init.sql
```

## Tables

| Table | Purpose |
|---|---|
| `ninjaye_installations` | install ID, machine label, token SHA-256, status |
| `ninjaye_sessions` | game instance, last activity, counters, metadata |
| `ninjaye_events` | discrete client/runtime events |
| `ninjaye_reports` | complete client/process/telemetry documents |
| `ninjaye_detections` | normalized detection code, severity, confidence, details |
| `ninjaye_artifacts` | raw file bytes, metadata, SHA-256 and size |

## Useful queries

Latest installations:

```sql
SELECT install_id, machine_label, disabled, created_at, last_seen_at
FROM ninjaye_installations
ORDER BY last_seen_at DESC;
```

Detection counts:

```sql
SELECT code, count(*) AS occurrences
FROM ninjaye_detections
GROUP BY code
ORDER BY occurrences DESC;
```

Installations with repeated high-severity detections:

```sql
SELECT installation_id, code, count(*) AS occurrences
FROM ninjaye_detections
WHERE severity >= 3
GROUP BY installation_id, code
HAVING count(*) >= 3
ORDER BY occurrences DESC;
```

Session timeline:

```sql
SELECT
    s.id,
    s.game_name,
    s.game_pid,
    s.started_at,
    s.last_heartbeat_at,
    count(e.id) AS events,
    count(r.id) AS reports
FROM ninjaye_sessions s
LEFT JOIN ninjaye_events e ON e.session_id = s.id
LEFT JOIN ninjaye_reports r ON r.session_id = s.id
GROUP BY s.id
ORDER BY s.started_at DESC;
```

Uploaded process-image inventory:

```sql
SELECT name, sha256, size_bytes, observed_at
FROM ninjaye_artifacts
ORDER BY received_at DESC;
```

The `content` column contains the exact `/file.php` multipart payload. Treat it
as untrusted binary data and apply a retention policy before exposing database
access to analysts.

## Retention

Retention is deliberately not hard-coded. Production deployments should add a
policy based on privacy requirements and database capacity. Reports and raw
metadata can be dropped or archived while normalized detections are retained
longer.
