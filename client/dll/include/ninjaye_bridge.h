#ifndef NINJAYE_BRIDGE_H
#define NINJAYE_BRIDGE_H

#include <stdint.h>

#if defined(_WIN32)
#define NINJAYE_BRIDGE_CALL __stdcall
#define NINJAYE_MESSAGE_CALL __cdecl
#else
#define NINJAYE_BRIDGE_CALL
#define NINJAYE_MESSAGE_CALL
#endif

#ifdef __cplusplus
extern "C"
{
#endif

typedef uint32_t(__cdecl* ninjaye_message_function)(uint32_t message);

typedef void(__cdecl* ninjaye_identity_function)(void* destination32);

typedef void(__stdcall* ninjaye_notify_callback)(
    uint32_t command,
    const void* buffer_or_pointer,
    uint32_t size);

#pragma pack(push, 1)
#if defined(_WIN64)
typedef struct ninjaye_client_config24
{
    uint32_t* marker;
    ninjaye_notify_callback callback;
    wchar_t* server_address;
} ninjaye_client_config24;
#else
typedef struct ninjaye_client_config24
{
    uint32_t* marker;
    ninjaye_notify_callback callback;
    wchar_t* server_address;
    uint8_t reserved[12];
} ninjaye_client_config24;
#endif
#pragma pack(pop)

#ifdef __cplusplus
static_assert(sizeof(ninjaye_client_config24) == 24);
#endif

#define NINJAYE_PROFILE_MARKER 0x4D543254u

#ifdef __cplusplus
}
#endif

#endif
