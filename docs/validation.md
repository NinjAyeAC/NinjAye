# Validation

## Native builds

- `Release|x64`: PASS;
- `Release|Win32`: PASS;
- `/W4 /WX`: PASS;
- C# server `net8.0`: PASS;
- Docker image on .NET 8: PASS.

## Semaphore/callback flow

Validated on both x86 and x64:

```text
SDK low-memory config
  -> CreateSemaphoreExW(Local\NinjAyePID, addr >> 31, addr & 7fffffff)
  -> marker 4D543254
  -> LoadLibraryW
  -> DLL opens/queries semaphore
  -> callback 0,5,4,3,2,1
  -> SDK ready after challenge and ClientId variants 1..5 are stored
```

The SDK received all five identity callbacks and copied exactly 32 bytes from
each of them.

## Challenge

The SDK calls command0 with `0x12345678`. An independent calculation over the
same DLL file CRC32C, profile mask `FFFFFFFF`, and the NinjAye operation order
produces the identical result. The expected output changes
whenever the DLL image changes, so no stale build-specific value is recorded
here.

## HTTP paths

The complete public server route inventory is:

```text
POST /status2.php
POST /event.php
POST /upload.php
POST /file.php
```

There are no other mapped endpoints. The former `/health`, `/admin/summary`
and `/api/v1/*` routes are absent and return `404`.

Controlled local tests passed:

| Test | Result |
|---|---|
| Binary MPNE `/status2.php` request/response | `200`, authenticated AES-GCM, nonce echo |
| Multipart MPNE `/upload.php` report | `200`, report persisted |
| Exact 60-byte XOR cache record to `/event.php` | `200`, event persisted |
| Multipart raw file to `/file.php` | `200`, file bytes and SHA-256 persisted |

Replaying the same event record or artifact returns `200` and updates the
existing row. This covers the retry workers without duplicating
events, reports or files.

## Automated end-to-end test

Run:

```powershell
.\tests\run_end_to_end.ps1
```

The test builds x64 and Win32, starts Docker/PostgreSQL, waits for the TCP
endpoint and runs the real native client. It verifies:

```text
five identity callbacks
AA challenge response
server-side opaque echo verification
status2 session creation
controlled region report upload
exact cache event submission
raw multipart file submission
cleanup of synthetic database rows
```

The controlled report now contains only predicate-backed findings. A clean SDK
run emits no report because unsigned modules, debugger APIs and process names
are not validated detection predicates. No severity-0 baseline or
unconditional process-report row is appended.

Report detections and thread/cache records use separate endpoints:
`ReportInternalEvent` rows go to `/upload.php`; `WriteCacheRecord` rows are sent
as exact 60-byte `/event.php` records.

`Reserved2` values from the status response gate `/file.php`, matching the
documented exact-key lookup. The five identity fields in status and reports are
independent collector outputs.

## String protection

The native projects compile MessagePack keys, endpoints, multipart metadata,
profile names and detector strings through `JustasMasiulis/xorstr`.
Automated binary scans check for representative plaintext keys, endpoints and
cheat-tool names. The SDK Release library is intentionally built without LTCG so
the `.lib` itself is clean; both x86 and x64 `NinjAye.Sdk.lib` and example
executables pass the representative-string scan.

## Compatibility boundaries

Detector branches without a complete validated predicate fail closed and do not
emit speculative findings. The validated semaphore configuration, callback
order, five identities, challenge arithmetic, HTTP routes, target hashing,
process selection, `Reserved2`, and file candidate construction are implemented
directly.

Passing the local suite proves the NinjAye client/server contract.
