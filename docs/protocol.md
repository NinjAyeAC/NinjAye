# HTTP protocol

The server exposes only four `POST` routes. There are no
administrative, health, versioned API or compatibility aliases.

| Route | Body | Success response |
|---|---|---|
| `/status2.php` | `application/octet-stream`, MPNE envelope | `200`, MPNE envelope |
| `/event.php` | `application/octet-stream`, one 60-byte cache record | `200`, empty body |
| `/upload.php` | multipart field `file`, MPNE report envelope | any `2xx`, empty body |
| `/file.php` | multipart field `file`, filename `application` | `200`, empty body |

Every route uses `Authorization: Bearer <process-token>`. NinjAye creates a new
token and install ID in memory on every process start and never reads them back
from disk. The server stores only the current token's SHA-256 hash. The first
valid `status2.php` request enrolls or refreshes the installation identified by
the hardware-derived `ClientId`.

## `/status2.php`

The request body is:

```text
"MPNE" | gcm_nonce[12] | gcm_tag[16] |
wrapped_aes_key[256] | ciphertext
```

The 32-byte AES key is RSA-2048 OAEP-SHA1 wrapped with NinjAye's generated
public key. AES is AES-256-GCM with no additional authenticated data.

The plaintext is an eight-field MessagePack map in this order:

```text
ServerId:    unsigned integer
Nonce:       32 uppercase hexadecimal characters
DllVersion:  "1.2.7.7" NinjAye wire version
ClientId:    32 hexadecimal characters
ClientIdV2:  32 hexadecimal characters
ClientIdV3:  current NinjAye output is 32 hexadecimal characters
ClientIdV4:  32 hexadecimal characters
ClientIdV5:  32 hexadecimal characters
```

The response uses the request's AES key and a fresh 12-byte GCM nonce. It is:

```text
"MPNE" | response_gcm_nonce[12] | gcm_tag[16] | ciphertext
```

The decrypted MessagePack map contains the echoed application `Nonce`, numeric
`Status`, `BlacklistedMD5s`, `Reserved1`, `Reserved2`, `Reserved3`, `Reserved4`
and optional `Reserved50`. NinjAye generates 20 deterministic blacklist fixture
rows and 20 Reserved1 fixture rows so the client's count validation
is exercised. `Reserved2` remains empty unless the server is configured with
approved file MD5 values. A status result of zero is the only accepted result
for a completed exchange.

Before MPNE parsing, the client applies its challenge-page rule:
HTTP 403 or an HTML content type, together with one of the configured
Cloudflare/access-denied body predicates. A detected challenge is reported as
a validation failure and is never passed to MessagePack as application data.

## `/event.php`

The request is exactly one 60-byte cache record:

```text
offset size
0x00   4    LCG seed
0x04   56   header XORed with the LCG stream
```

Decoded header layout:

```text
0x00 4   magic, 0x8D3C51A7
0x04 2   version, 1
0x06 2   header size, 56
0x08 8   Windows FILETIME
0x10 4   process ID
0x14 4   thread ID
0x18 8   GetTickCount64 value
0x20 4   argument0 / event class
0x24 8   argument2 / event value
0x2C 4   argument1 / event code
0x30 4   selected profile/server ID
0x34 4   build constant, 0x01020707
```

The XOR state is unsigned 32-bit:

```text
state = seed != 0 ? seed : 0xA12F6C3D
state = state * 1664525 + 1013904223
header_byte ^= uint8(state >> 24)
```

The endpoint accepts only an authenticated, structurally valid record and
returns the exact `200` status expected by the client.

## `/upload.php`

The multipart body has one text/header section:

```text
Content-Disposition: form-data; name="file"; filename="<36 uppercase A-Z/0-9>"
Content-Type: application/octet-stream
```

The file content is an MPNE envelope. Its plaintext is a MessagePack report
map. Client information is nested under
`ClientInformation`:

```text
ClientInformation {
  ReportType, DllVersion, DllBase, DllImageHash,
  ClientId, ClientIdV2, ClientIdV3_1, ClientIdV4, ClientIdV5,
  ServerId, ServerName, Timestamp, ComputerName, UserName
}
ProcessInformation, Telemetry, Detections
```

`ProcessInformation`, `Telemetry` and `Detections` are native MessagePack
objects and arrays, not JSON strings. `ProcessInformation.Heuristics` carries
the same report rows as the top-level `Detections` array for compatibility
with the NinjAye server.

Each heuristic row includes these fields:

```text
Heur, Points, Flags, IsExperimental, IsBeta, Timestamp,
String1, Qword1
```

`String1` remains a string even when its contents look like JSON.

`DllBase` is an eight-digit uppercase hexadecimal string, while the full native
address remains available in
`ProcessInformation.dllBase` on 64-bit builds. `DllImageHash` is the uppercase
MD5 of the NinjAye DLL image. `ClientIdV3_1` is distinct from the status
request's `ClientIdV3`.

The server authenticates the client, decrypts and authenticates the envelope,
validates the MessagePack map, stores the complete report, and returns `200`
with an empty body. The client does not inspect the response body.

## `/file.php`

The multipart field is exactly:

```text
name="file"
filename="application"
Content-Type: application/octet-stream
```

The payload is raw file content with no encryption layer. The client accepts
files from 5 through 25,000,000 bytes, zero-fills a short read, and does not
test the response. The server stores the raw bytes plus their SHA-256 and
returns an empty `200` response.

The source path is never sent as the multipart filename. The
`Reserved2` lookup controls whether a candidate process image, PDB or companion
DLL is submitted.

## Endpoint parity

`GET /health`, `GET /admin/summary`, `/api/v1/*`, action-based JSON and any
method other than `POST` on the four NinjAye paths are deliberately absent.
The server's public route inventory is exactly:

```text
POST /status2.php
POST /event.php
POST /upload.php
POST /file.php
```
