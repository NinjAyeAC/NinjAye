# Client and server integration

## Files placed with the game

```text
GameDirectory\
  metin2client.exe
  NinjAye.dll
  ...existing game files...
```

## Solution layout

Open `NinjAye.sln` in Visual Studio 2022. The solution contains:

- `NinjAye.Dll`;
- `NinjAye.Sdk`;
- `NinjAye.Example`;
- `NinjAye.Server`;
- SQL and documentation solution folders.

The DLL project runs `scripts/generate-dev-keys.ps1` before compilation. It
creates an ignored local RSA pair and the generated public-key header when one
is missing. Select the matching platform (`Win32` for a 32-bit game, `x64` for
a 64-bit game) and build the solution.

The SDK loader can also resolve the DLL by absolute path:

```cpp
ninjaye::client protection;
if (!protection.load(L"C:\\Games\\NinjAye.dll"))
{
    const uint32_t error = static_cast<uint32_t>(protection.error_code());
    // Handle the numeric error code.
}
```

## Client startup call

Add one startup call after the game has a window and before gameplay begins:

```cpp
protection.start(L"https://protect.example.com");
```

`protection.start` internally performs the semaphore/callback startup.
It does not call the DLL's optional diagnostic exports.

The API base URL is supplied to `protection.start`. The SDK stores it in the
client bridge configuration and the DLL reads it through the semaphore
handshake. Game name, profile, status interval and detection interval remain
compile-time values. The only configured server profile is `Mt2Test`, with
server ID `1` and marker `4D543254`.

Every `protection.start` creates a new token and install ID in memory. They are
never written to disk or reused by a later process. The first authenticated
`/status2.php` request enrolls or refreshes the installation keyed by the
hardware-derived `ClientId`.

Call `protection.stop()` during an orderly game shutdown. If the process exits
without this call, Windows still terminates the worker threads.

## Loading options

1. **Explicit SDK**: link `ninjaye_sdk.cpp` and ship `NinjAye.dll` beside the
   executable.
2. **Delayed startup**: call `protection.start()` after the main game window
   exists. This still uses the semaphore/callback handshake and does
   not resolve an export.

## Challenge and identity

The SDK receives the command0 function during startup:

```cpp
uint32_t reply = 0;
protection.resolve_challenge(packet.message, reply);
```

For `AA` packets, send:

```text
AA | same eight opaque bytes | reply
```

Commands `1..5` copy the five 32-byte ClientId variants:

```cpp
std::array<uint8_t, 32> identity_v1 = {};
std::array<uint8_t, 32> identity_v2 = {};
std::array<uint8_t, 32> identity_v3 = {};
std::array<uint8_t, 32> identity_v4 = {};
std::array<uint8_t, 32> identity_v5 = {};

protection.copy_machine_identity(identity_v1);
protection.copy_cpu_disk_identity(identity_v2);
protection.copy_tpm_identity(identity_v3);
protection.copy_profile_list_identity(identity_v4);
protection.copy_file_id_identity(identity_v5);
```

The callback contract is represented by
`ninjaye::notification_command::{challenge, client_id, client_id_v2,
client_id_v3, client_id_v4, client_id_v5}`. `start()` waits until the challenge
and all five identity functions have been published.

Do not place static server-wide credentials in the client.

## Server deployment

1. Run `scripts/initialize-development.ps1` to generate local keys and a random
   development password.
2. For production, use the deployment secret manager to provide the database
   password and RSA private key.
3. Keep the public key in `NinjAye.dll` and the private key only in the server.
4. Put the server behind a TLS reverse proxy.
5. Run `docker compose up -d --build`.
6. Pass the TLS endpoint to `protection.start()` from the game SDK.

The client supports `http://127.0.0.1` for development. Production must use
HTTPS.

The server mounts the client routes at:

```text
POST /status2.php
POST /event.php
POST /upload.php
POST /file.php
```

These four routes are the entire public endpoint inventory. There is no health,
administration or `/api/v1` route.

`/status2.php` is the MPNE/AES-GCM/RSA-OAEP exchange.
`/event.php` accepts one raw 60-byte cache record. `/upload.php` accepts a
multipart MPNE report envelope. `/file.php` accepts one raw multipart file with
field `file` and filename `application`. See [protocol](protocol.md) for exact
wire layouts.

## What must exist on the game server/client

The client only requires:

- `NinjAye.dll`;
- SDK loader or equivalent `LoadLibraryW` code;
- startup and shutdown calls;
- network access to the NinjAye API.

The server environment requires:

- ASP.NET Core runtime or Docker;
- PostgreSQL;
- persistent volume for the database;
- TLS termination and backup policy.
