# End-to-end tests

Run from PowerShell:

```powershell
$env:NINJAYE_PLATFORM_TOOLSET = "v143"
.\tests\run_end_to_end.ps1
```

Use `-SkipBuild` when the solution is already built. Use `-SkipWin32` to test
only x64. Use `-KeepTestData` to retain the synthetic installation, event and
artifact for inspection. Every normal run uses an isolated Compose project,
random database password and disposable PostgreSQL volume.

The Windows GitHub runner uses the host PostgreSQL service instead of Docker
because its Docker daemon runs Windows containers:

```powershell
$env:NINJAYE_TEST_POSTGRES_PASSWORD = "<random CI password>"
.\tests\run_end_to_end.ps1 -NativeServer
```

The harness calls `scripts/initialize-development.ps1` before starting the
stack. It requires Docker, Docker Compose, Visual Studio/MSBuild, curl and
PowerShell.

The script checks:

- native client build;
- Win32 client build and challenge;
- PostgreSQL and server startup;
- status/MPNE handshake;
- all five identity callbacks;
- 13-byte `AA` challenge request and response;
- server-side CRC32C and full challenge arithmetic;
- `challenge_reply.message` equality verification;
- opaque echo verification;
- session and identity counts in PostgreSQL;
- report upload from a controlled private RWX region;
- nested `ClientInformation`, MD5 image hash and expected report field keys;
- exact 60-byte cache event submission;
- raw multipart file submission and SHA-256 persistence;
- cleanup of synthetic test data.
