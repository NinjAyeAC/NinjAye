# Adding the NinjAye GC packet

NinjAye uses a 13-byte `0xAA` game packet.

## Wire layout

```cpp
#pragma pack(push, 1)
struct gc_ninjaye_packet
{
    uint8_t header;
    uint8_t opaque_echo[8];
    uint32_t message;
};
#pragma pack(pop)

static_assert(sizeof(gc_ninjaye_packet) == 13);
```

`message` is a native little-endian `uint32_t`.

## SDK startup

Load the DLL and pass the server address through the SDK:

```cpp
ninjaye::client protection;
protection.load(L"C:\\Games\\NinjAye.dll");
protection.start(L"https://protect.example.com");
```

The SDK then follows the client startup:

```text
Local\NinjAye<PID> semaphore
-> 24-byte bridge configuration
-> marker 4D543254
-> server URL pointer
-> LoadLibraryW
-> wait for command0..5
```

No environment variable or DLL export is used.

## Registering the incoming packet

Register header `0xAA` with a fixed size of 13 bytes during game packet-table
initialization:

```cpp
packet_map.set_static_size(0xAA, sizeof(gc_ninjaye_packet));
```

## Handler

```cpp
bool handle_gc_ninjaye_packet(
    std::span<const uint8_t> incoming,
    ninjaye::client& protection,
    std::array<uint8_t, 13>& outgoing)
{
    if (incoming.size() != sizeof(gc_ninjaye_packet))
        return false;

    gc_ninjaye_packet request = {};
    std::memcpy(&request, incoming.data(), sizeof(request));
    if (request.header != 0xAA)
        return false;

    gc_ninjaye_packet response = {};
    response.header = 0xAA;
    std::memcpy(
        response.opaque_echo,
        request.opaque_echo,
        sizeof(response.opaque_echo));

    if (!protection.resolve_challenge(
            request.message,
            response.message))
    {
        return false;
    }

    std::memcpy(
        outgoing.data(),
        &response,
        sizeof(response));
    return true;
}
```

The complete 13 input bytes are consumed before the command0 function is
called. The response echoes the same eight opaque bytes and replaces only the
four-byte message.

## Game-server flow

1. Generate an opaque eight-byte session tag.
2. Generate a 32-bit challenge.
3. Send `AA | opaque[8] | challenge32`.
4. Receive `AA | opaque[8] | reply32`.
5. Require the echoed opaque bytes to match.
6. Validate `reply32` using the server-side challenge rule.

This exchange travels on the existing game socket. It is not `/status2.php`,
not `/event.php`, and it does not expose the API bearer token.
