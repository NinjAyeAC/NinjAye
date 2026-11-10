# Changelog

All notable changes to NinjAye are documented here.

## [0.1.0] - 2026-11-10

### Added

- Native `NinjAye.dll` with bridge callbacks, identities, detections and
  runtime reporting.
- C++20 integration SDK and executable `AA` packet example.
- ASP.NET Core 8 server with the four supported POST endpoints.
- PostgreSQL schema with `jsonb` report and detection storage.
- x64/Win32 end-to-end test harness.
- Local development key and environment bootstrap.
- Visual Studio 2022 solution, documentation and GitHub CI.
- Compatibility and fail-closed behavior classifications.

### Security

- Removed tracked private RSA material and hardcoded database credentials.
- Added ignore rules for secrets, build products and local test state.
- Mounted the development private key into the server container at runtime.
- Removed process-handle and process-detail detections that lacked a complete
  validated predicate.
