# NinjAye SDK

```cpp
#include "ninjaye_sdk.h"

ninjaye::client protection;
protection.load(L"C:\\Games\\NinjAye.dll");
protection.start(L"https://protect.example.com");
```

All client configuration is compiled into `NinjAye.dll` through
`static_client_config.cpp`. There is one profile: `Mt2Test`, server ID `1`,
marker `4D543254`. The server URL is supplied by the SDK and transferred
through the client bridge configuration; no environment variable is read.

The loader performs no `GetProcAddress` lookup and calls no DLL export. The
DLL starts its core through the semaphore/callback contract.

The SDK startup is deliberately not a direct `ninjaye_start` call. It recreates
the client handshake:

```text
low 24-byte config
  -> CreateSemaphoreExW(Local\NinjAyePID, addr >> 31, addr & 7fffffff)
  -> marker 4D543254
  -> LoadLibraryW(NinjAye.dll)
  -> wait for callback enum values 0 through 5
```

`ninjaye::notification_command` describes the published callback contract:

| Value | Enum | Published function |
|---:|---|---|
| `0` | `challenge` | `resolve_challenge(uint32_t) -> uint32_t` |
| `1` | `client_id` | copy `ClientId` |
| `2` | `client_id_v2` | copy CPU/disk `ClientIdV2` |
| `3` | `client_id_v3` | copy TPM-backed `ClientIdV3` |
| `4` | `client_id_v4` | copy profile-list `ClientIdV4` |
| `5` | `client_id_v5` | copy file-ID `ClientIdV5` |

The SDK stores every published function before `start()` completes. It exposes
named methods and a generic method:

```cpp
uint32_t response = 0;
protection.resolve_challenge(message, response);

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

std::array<uint8_t, 32> identity = {};
protection.copy_identity(
    ninjaye::notification_command::client_id_v4,
    identity);
```

Lifecycle failures are reported as stable numeric `ninjaye::sdk_error` values.
The SDK does not construct or store error description strings:

| Code | Enum value |
| --- | --- |
| `0x00000000` | `sdk_error::none` |
| `0x00010001` | `sdk_error::dll_path_invalid` |
| `0x00010002` | `sdk_error::dll_path_missing` |
| `0x00020001` | `sdk_error::low_config_allocation_failed` |
| `0x00020002` | `sdk_error::semaphore_name_too_long` |
| `0x00020003` | `sdk_error::server_address_invalid` |
| `0x00020004` | `sdk_error::startup_config_unencodable` |
| `0x00030001` | `sdk_error::create_semaphore_failed` |
| `0x00030002` | `sdk_error::load_library_failed` |
| `0x00040001` | `sdk_error::another_instance_active` |
| `0x00050001` | `sdk_error::message_function_missing` |
| `0x00050002` | `sdk_error::identity_function_missing` |

Use `static_cast<uint32_t>(protection.error_code())` when a numeric ABI value
is needed. Every `start()` clears the previous lifecycle error before beginning
the new handshake.

The loaded module handle is intentionally not freed. This matches the expected
client lifecycle, where the DLL remains loaded for the process lifetime.

All protocol-facing strings are compiled through the vendored
`JustasMasiulis/xorstr` header. The SDK also disables whole-program optimization
for its own Release build because MSVC otherwise stores pre-link LTCG bytecode
containing the source literals in the static `.lib`.

Build the `NinjAye.Sdk` and `NinjAye.Example` projects from `NinjAye.sln` in
Visual Studio 2022, using `Release|x64` or `Release|Win32`.

The game packet integration is documented in
[`docs/gc_packet.md`](../../docs/gc_packet.md).
