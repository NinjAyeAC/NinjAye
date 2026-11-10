#ifndef NINJAYE_H
#define NINJAYE_H

#include <stdint.h>
#include <wchar.h>

#if defined(_WIN32)
#if defined(NINJAYE_EXPORTS)
#define NINJAYE_API __declspec(dllexport)
#else
#define NINJAYE_API __declspec(dllimport)
#endif
#define NINJAYE_CALL __cdecl
#else
#define NINJAYE_API
#define NINJAYE_CALL
#endif

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct ninjaye_status
{
    int32_t running;
    int32_t enrolled;
    char install_id[64];
    char session_id[64];
    uint64_t events_sent;
    uint64_t reports_sent;
    uint64_t detections_seen;
    uint64_t files_attempted;
    uint64_t files_sent;
    int32_t last_http_status;
    wchar_t last_error[256];
} ninjaye_status;

NINJAYE_API int32_t NINJAYE_CALL ninjaye_start(void);

NINJAYE_API void NINJAYE_CALL ninjaye_stop(void);

NINJAYE_API int32_t NINJAYE_CALL ninjaye_report_event(
    const char* type,
    int32_t severity,
    const char* json_data);

NINJAYE_API int32_t NINJAYE_CALL ninjaye_get_status(
    ninjaye_status* status);

NINJAYE_API const char* NINJAYE_CALL ninjaye_version(void);

#ifdef __cplusplus
}
#endif

#endif
