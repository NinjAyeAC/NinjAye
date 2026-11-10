# NinjAye.Server

ASP.NET Core 8 ingestion API.

The HTTP host is intentionally small:

```text
Program.cs
  -> ServerComposition.cs
  -> Endpoints/EndpointRoutes.cs
  -> Services/ClientSessionService.cs
  -> Parsing/ReportIngestionParser.cs
```

`Program.cs` only configures dependency injection, starts the selected storage
backend and maps the four endpoint handlers.

Local memory mode:

```powershell
.\..\..\scripts\generate-dev-keys.ps1
$env:NinjAye__Storage = "memory"
$env:NinjAye__PrivateKeyPath =
  (Resolve-Path .\..\..\config\ninjaye-dev-private.pem)
dotnet run
```

PostgreSQL mode:

```powershell
.\..\..\scripts\initialize-development.ps1
$env:NinjAye__Storage = "postgres"
$env:NinjAye__PrivateKeyPath =
  (Resolve-Path .\..\..\config\ninjaye-dev-private.pem)
$env:POSTGRES_PASSWORD = "<value from .env>"
$env:ConnectionStrings__Postgres =
  "Host=127.0.0.1;Port=5432;Database=ninjaye;Username=ninjaye;Password=$env:POSTGRES_PASSWORD"
dotnet run
```

The schema is applied from `database/001_init.sql` at startup.

`NinjAye:PrivateKeyPath` is required. No private key is compiled into the
server or copied into its Docker image.

## Session model

The server uses a session model centered on the four supported endpoints:

- an installation represents the hardware-derived ClientId;
- a session represents one process token lifecycle;
- `/status2.php` creates or refreshes the session and stores all five identity
  values;
- `/event.php`, `/upload.php` and `/file.php` update the same session, its
  counters and its last JSON activity;
- a new process token derives a new session ID, matching the client behavior
  where token and install ID are generated in memory at every process start.

The session ID is derived from the persisted installation UUID and the
SHA-256 token hash. The raw bearer token is never stored.

## JSONB storage

PostgreSQL uses `jsonb` for:

- session identities, metadata and last endpoint activity;
- event payloads;
- normalized client, process and telemetry report trees;
- detection details;
- artifact metadata.

For example, report strings containing JSON objects or arrays are parsed and
stored as native `jsonb` trees rather than JSON strings. GIN indexes are
created for session metadata, event data, report snapshots, detection details
and artifact metadata.

## File submission policy

The client calls `/file.php` only after process selection and the
exact `Reserved2` MD5 gate. PostgreSQL or JSON configuration can supply the
allow-list:

```json
{
  "NinjAye": {
    "Reserved2": [
      "39417AF218CA9916633D4D9C979DC443"
    ],
    "Reserved50": 262144
  }
}
```

Environment equivalent:

```powershell
$env:NinjAye__Reserved2__0 = "39417AF218CA9916633D4D9C979DC443"
$env:NinjAye__Reserved50 = "262144"
```

Values are exact, case-sensitive 32-character MD5 strings. An empty list denies
all files whose digest has the expected length of 32 characters.
