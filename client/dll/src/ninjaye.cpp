#include "../include/ninjaye.h"

#include "bridge_runtime.h"
#include "detection_engine.h"
#include "http_client.h"
#include "input_capture.h"
#include "json_utils.h"
#include "process_collection.h"
#include "runtime_events.h"
#include "runtime_identity.h"
#include "splash_window.h"
#include "static_client_config.h"
#include "wire_protocol.h"

#include <xorstr.hpp>
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace ninjaye
{
namespace
{
struct runtime_state
{
    std::mutex lifecycle_mutex;
    std::mutex error_mutex;
    std::mutex process_config_mutex;
    std::atomic<bool> running = false;
    std::atomic<bool> stop_requested = false;
    std::atomic<bool> enrolled = false;
    std::atomic<uint64_t> events_sent = 0;
    std::atomic<uint64_t> reports_sent = 0;
    std::atomic<uint64_t> detections_seen = 0;
    std::atomic<uint64_t> files_attempted = 0;
    std::atomic<uint64_t> files_sent = 0;
    std::atomic<int32_t> last_http_status = 0;
    std::atomic<bool> status_transport_failed = false;
    std::atomic<bool> status_result_failed = false;
    std::wstring base_url;
    std::wstring game_name;
    std::wstring profile_name;
    uint32_t profile_id = 0;
    uint64_t event_mask = 0;
    uint32_t detection_interval_ms = 30000;
    uintptr_t dll_base = 0;
    std::string install_id;
    std::string token;
    std::string session_id;
    std::string dll_path;
    std::string dll_sha256;
    std::string dll_image_hash;
    std::string game_path;
    identity_snapshot identity;
    std::vector<std::string> reserved2_keys;
    std::string last_error;
    std::chrono::steady_clock::time_point started_at;
    std::thread splash_thread;
    std::thread process_thread;
    std::thread worker_thread;
};

runtime_state g_state;

void set_error(const std::string& error)
{
    std::lock_guard<std::mutex> lock(g_state.error_mutex);
    g_state.last_error = error;
}

std::string wire_error_message(const wire_error error)
{
    switch (error)
    {
    case wire_error::none:
        return {};
    case wire_error::invalid_argument:
        return xorstr_("wire.invalid_argument");
    case wire_error::crypto_random_failed:
        return xorstr_("wire.crypto_random_failed");
    case wire_error::crypto_aes_gcm_failed:
        return xorstr_("wire.crypto_aes_gcm_failed");
    case wire_error::crypto_rsa_oaep_failed:
        return xorstr_("wire.crypto_rsa_oaep_failed");
    case wire_error::protocol_nonce_failed:
        return xorstr_("wire.protocol_nonce_failed");
    case wire_error::messagepack_encode_failed:
        return xorstr_("wire.messagepack_encode_failed");
    case wire_error::report_identity_missing:
        return xorstr_("wire.report_identity_missing");
    case wire_error::report_encode_failed:
        return xorstr_("wire.report_encode_failed");
    case wire_error::transport_failed:
        return xorstr_("wire.transport_failed");
    case wire_error::challenge_detected:
        return xorstr_("wire.challenge_detected");
    case wire_error::response_http_status:
        return xorstr_("wire.response_http_status");
    case wire_error::response_too_small:
        return xorstr_("wire.response_too_small");
    case wire_error::response_too_large:
        return xorstr_("wire.response_too_large");
    case wire_error::response_not_mpne:
        return xorstr_("wire.response_not_mpne");
    case wire_error::response_nonce_reused:
        return xorstr_("wire.response_nonce_reused");
    case wire_error::response_decrypt_failed:
        return xorstr_("wire.response_decrypt_failed");
    case wire_error::response_map_invalid:
        return xorstr_("wire.response_map_invalid");
    case wire_error::response_key_invalid:
        return xorstr_("wire.response_key_invalid");
    case wire_error::response_nonce_invalid:
        return xorstr_("wire.response_nonce_invalid");
    case wire_error::response_status_invalid:
        return xorstr_("wire.response_status_invalid");
    case wire_error::response_array_invalid:
        return xorstr_("wire.response_array_invalid");
    case wire_error::response_array_row_invalid:
        return xorstr_("wire.response_array_row_invalid");
    case wire_error::response_reserved2_invalid:
        return xorstr_("wire.response_reserved2_invalid");
    case wire_error::response_reserved2_row_invalid:
        return xorstr_("wire.response_reserved2_row_invalid");
    case wire_error::response_value_invalid:
        return xorstr_("wire.response_value_invalid");
    case wire_error::response_nonce_mismatch:
        return xorstr_("wire.response_nonce_mismatch");
    case wire_error::response_status_missing:
        return xorstr_("wire.response_status_missing");
    case wire_error::response_blacklist_short:
        return xorstr_("wire.response_blacklist_short");
    case wire_error::response_reserved1_short:
        return xorstr_("wire.response_reserved1_short");
    case wire_error::status_rejected:
        return xorstr_("wire.status_rejected");
    default:
        return xorstr_("wire.unknown_") +
            std::to_string(static_cast<uint32_t>(error));
    }
}

void set_wire_error(const wire_error error)
{
    set_error(wire_error_message(error));
}

void clear_error()
{
    std::lock_guard<std::mutex> lock(g_state.error_mutex);
    g_state.last_error.clear();
}

std::string game_executable_path()
{
    std::vector<wchar_t> buffer(32768);
    const DWORD length = GetModuleFileNameW(
        nullptr,
        buffer.data(),
        static_cast<DWORD>(buffer.size()));
    if (length == 0)
    {
        return {};
    }
    return utf8_from_wide(std::wstring(buffer.data(), length));
}

std::string current_dll_path()
{
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&ninjaye_start),
            &module))
    {
        return {};
    }

    std::vector<wchar_t> buffer(32768);
    const DWORD length = GetModuleFileNameW(
        module,
        buffer.data(),
        static_cast<DWORD>(buffer.size()));
    if (length == 0)
    {
        return {};
    }
    return utf8_from_wide(std::wstring(buffer.data(), length));
}

uintptr_t current_dll_base()
{
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&ninjaye_start),
            &module))
    {
        return 0;
    }
    return reinterpret_cast<uintptr_t>(module);
}

bool response_is_success(const http_response& response)
{
    return response.transport_ok &&
        response.status_code >= 200 &&
        response.status_code < 300;
}

bool exchange_status()
{
    g_state.status_transport_failed = false;
    g_state.status_result_failed = false;
    status_exchange_material material;
    wire_error build_error = wire_error::none;
    if (!build_status_request(
            g_state.identity,
            g_state.profile_id,
            material,
            build_error))
    {
        g_state.enrolled = false;
        g_state.status_result_failed = true;
        set_wire_error(build_error);
        return false;
    }
    const http_response response = http_post_bytes(
        g_state.base_url,
        xorstr_("/status2.php"),
        material.body,
        g_state.token,
        xorstr_("application/octet-stream"));
    g_state.last_http_status = response.status_code;

    status_response_result status_result;
    if (!consume_status_response(response, material, status_result))
    {
        g_state.enrolled = false;
        g_state.status_transport_failed = !response.transport_ok;
        g_state.status_result_failed =
            response.transport_ok ||
            status_result.error != wire_error::transport_failed;
        set_wire_error(
            status_result.error == wire_error::none
            ? wire_error::transport_failed
            : status_result.error);
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(
            g_state.process_config_mutex);
        g_state.reserved2_keys = status_result.reserved2_keys;
        g_state.event_mask = status_result.event_mask;
    }
    g_state.enrolled = true;
    clear_error();
    return true;
}

HANDLE open_path_file(const std::wstring& path)
{
    HANDLE file = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file != INVALID_HANDLE_VALUE ||
        GetLastError() != ERROR_FILE_NOT_FOUND)
    {
        return file;
    }

    void* redirection = nullptr;
    Wow64DisableWow64FsRedirection(&redirection);
    file = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    Wow64RevertWow64FsRedirection(redirection);
    return file;
}

std::vector<uint8_t> read_file_bytes(const std::wstring& path)
{
    const HANDLE file = open_path_file(path);
    if (file == INVALID_HANDLE_VALUE)
    {
        return {};
    }

    LARGE_INTEGER file_size = {};
    if (!GetFileSizeEx(file, &file_size) ||
        file_size.QuadPart < 5 ||
        file_size.QuadPart > 25000000LL)
    {
        CloseHandle(file);
        return {};
    }

    std::vector<uint8_t> bytes(
        static_cast<size_t>(file_size.QuadPart),
        0);
    DWORD read = 0;
    (void)ReadFile(
        file,
        bytes.data(),
        static_cast<DWORD>(bytes.size()),
        &read,
        nullptr);
    CloseHandle(file);
    return bytes;
}

void report_path_file(const std::wstring& path)
{
    const std::vector<uint8_t> bytes = read_file_bytes(path);
    if (bytes.empty())
    {
        return;
    }
    ++g_state.files_attempted;
    const multipart_payload multipart = build_multipart_file(bytes);
    const http_response response = http_post_bytes(
        g_state.base_url,
        xorstr_("/file.php"),
        multipart.body,
        g_state.token,
        multipart.content_type);
    g_state.last_http_status = response.status_code;
    if (response_is_success(response))
    {
        ++g_state.files_sent;
    }
}

void report_selected_process_file(const std::wstring& path)
{
    report_path_file(path);
}

bool send_cache_event(
    uint32_t event_code,
    uint32_t event_action,
    uint64_t event_value);

bool send_detection_report()
{
    detection_snapshot snapshot = {};
    const bridge_integrity_observation integrity =
        observe_bridge_integrity();
    detection_runtime_context runtime;
    runtime.callback_registry_ready =
        integrity.callback_registry_ready;
    runtime.callback_kind_count =
        integrity.callback_kind_count;
    runtime.status_transport_failed =
        g_state.status_transport_failed.load();
    runtime.status_result_failed =
        g_state.status_result_failed.load();
    runtime.challenge_repeated =
        integrity.challenge_repeated;
    runtime.challenge_repeat_count =
        integrity.challenge_repeat_count;
    runtime.module_crc_mismatch =
        integrity.module_crc_mismatch;
    runtime.module_crc =
        integrity.module_crc;
    std::string error;
    if (!collect_detection_snapshot(
            g_state.dll_path,
            g_state.dll_sha256,
            runtime,
            snapshot,
            error))
    {
        set_error(error.empty()
            ? xorstr_("detection_collection_failed")
            : error);
        return false;
    }
    for (const raw_cache_event& event : snapshot.cache_events)
    {
        (void)send_cache_event(
            event.type,
            event.code,
            event.value);
    }
    if (snapshot.detection_count == 0)
    {
        clear_error();
        return true;
    }

    report_wire_input input = {};
    input.identity = &g_state.identity;
    input.server_id = g_state.profile_id;
    input.profile_name = utf8_from_wide(g_state.profile_name);
    input.dll_image_hash = g_state.dll_image_hash;
    input.dll_base = g_state.dll_base;
    input.process_json = snapshot.process_json;
    input.telemetry_json = snapshot.telemetry_json;
    input.detections_json = snapshot.detections_json;

    wire_error report_error = wire_error::none;
    std::vector<uint8_t> envelope;
    if (!build_report_envelope(input, envelope, report_error))
    {
        set_wire_error(report_error);
        return false;
    }
    const multipart_payload multipart = build_multipart_report(
        envelope,
        random_report_filename());
    g_state.detections_seen += snapshot.detection_count;
    const http_response response = http_post_bytes(
        g_state.base_url,
        xorstr_("/upload.php"),
        multipart.body,
        g_state.token,
        multipart.content_type);
    g_state.last_http_status = response.status_code;
    if (!response_is_success(response))
    {
        std::string detail = xorstr_("report_upload_failed_http=") +
            std::to_string(response.status_code);
        if (!response.body.empty())
        {
            detail += xorstr_(" body=") + response.body.substr(0, 512);
        }
        set_error(detail);
        return false;
    }

    ++g_state.reports_sent;
    clear_error();
    return true;
}

bool send_cache_event(
    const uint32_t event_code,
    const uint32_t event_action,
    const uint64_t event_value)
{
    const std::vector<uint8_t> body = build_cache_event(
        event_code,
        event_action,
        event_value,
        GetCurrentProcessId(),
        g_state.profile_id);
    const http_response response = http_post_bytes(
        g_state.base_url,
        xorstr_("/event.php"),
        body,
        g_state.token,
        xorstr_("application/octet-stream"));
    g_state.last_http_status = response.status_code;
    if (!response.transport_ok ||
        response.status_code != 200)
    {
        return false;
    }
    ++g_state.events_sent;
    return true;
}

bool send_event(
    const std::string& type,
    const int32_t severity,
    const std::string& json_data)
{
    const uint32_t argument0 = static_cast<uint32_t>(
        std::hash<std::string>{}(type) & 0x7FFFFFFF);
    const uint32_t argument1 =
        static_cast<uint32_t>(severity < 0 ? 0 : severity + 0x200);
    const uint64_t argument2 =
        std::hash<std::string>{}(json_data);
    return send_cache_event(argument0, argument1, argument2);
}

void sleep_briefly()
{
    for (int index = 0; index < 10 && !g_state.stop_requested.load(); ++index)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void process_worker_loop()
{
    auto next_scan = std::chrono::steady_clock::now();
    while (!g_state.stop_requested.load())
    {
        const auto now = std::chrono::steady_clock::now();
        if (now >= next_scan)
        {
            std::vector<std::string> reserved2_keys;
            uint64_t event_mask = 0;
            {
                std::lock_guard<std::mutex> lock(
                    g_state.process_config_mutex);
                reserved2_keys = g_state.reserved2_keys;
                event_mask = g_state.event_mask;
            }
            process_collection_config config;
            config.current_process_id = GetCurrentProcessId();
            config.profile_flags =
                selected_static_profile().process_flags;
            config.event_mask = event_mask;
            config.reserved2_keys = &reserved2_keys;
            (void)collect_process_files_once(
                config,
                &report_selected_process_file);
            next_scan = now + std::chrono::milliseconds(1500);
        }
        sleep_briefly();
    }
}

void worker_loop()
{
    auto next_status = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(k_status_interval_ms);
    auto next_detection = std::chrono::steady_clock::now();

    while (!g_state.stop_requested.load())
    {
        const auto now = std::chrono::steady_clock::now();
        if (now >= next_status)
        {
            exchange_status();
            next_status = now +
                std::chrono::milliseconds(k_status_interval_ms);
        }
        if (now >= next_detection)
        {
            send_detection_report();
            next_detection = now +
                std::chrono::milliseconds(g_state.detection_interval_ms);
        }
        sleep_briefly();
    }
}

}

bool report_cache_record(
    const uint32_t event_type,
    const uint32_t event_code,
    const uint64_t event_value)
{
    if (!g_state.running.load())
    {
        return false;
    }
    return send_cache_event(
        event_type,
        event_code,
        event_value);
}

}

extern "C"
{
int32_t NINJAYE_CALL ninjaye_start(void)
{
    using namespace ninjaye;

    std::lock_guard<std::mutex> lock(g_state.lifecycle_mutex);
    if (g_state.running.load())
    {
        return 1;
    }

    g_state.stop_requested = false;
    clear_error();
    const static_profile& profile = selected_static_profile();
    g_state.base_url = runtime_server_url();
    if (g_state.base_url.empty())
    {
        set_error(xorstr_("server_address_missing"));
        return 0;
    }
    g_state.game_name = static_game_name();
    g_state.profile_name = static_profile_name(profile.server_id);
    g_state.profile_id = profile.server_id;
    g_state.detection_interval_ms = k_detection_interval_ms;
    g_state.started_at = std::chrono::steady_clock::now();
    g_state.game_path = game_executable_path();
    g_state.dll_path = current_dll_path();
    g_state.dll_base = current_dll_base();
    g_state.dll_sha256 = sha256_file_hex(wide_from_utf8(g_state.dll_path));
    g_state.dll_image_hash =
        md5_file_hex(wide_from_utf8(g_state.dll_path));
    g_state.session_id = new_guid_string();

#ifndef NINJAYE_DISABLE_SPLASH
    if (bridge_claim_splash())
    {
        g_state.splash_thread = std::thread(run_splash_window);
    }
#endif

    client_identity identity = {};
    std::string identity_error;
    if (!create_client_identity(
            g_state.base_url,
            identity,
            identity_error))
    {
        set_error(identity_error);
        if (g_state.splash_thread.joinable())
        {
            g_state.splash_thread.join();
        }
        return 0;
    }

    g_state.install_id = identity.install_id;
    g_state.token = identity.token;
    g_state.identity = {};
    if (!collect_identity_snapshot(g_state.identity, identity_error))
    {
        set_error(
            identity_error.empty()
            ? xorstr_("identity_collection_failed")
            : identity_error);
        if (g_state.splash_thread.joinable())
        {
            g_state.splash_thread.join();
        }
        return 0;
    }

    g_state.enrolled = false;
    if (!exchange_status())
    {
        if (g_state.splash_thread.joinable())
        {
            g_state.splash_thread.join();
        }
        return 0;
    }

    clear_error();
    (void)start_input_capture();
    reset_process_collection();
    g_state.running = true;
    g_state.process_thread = std::thread(process_worker_loop);
    g_state.worker_thread = std::thread(worker_loop);
    return 1;
}

void NINJAYE_CALL ninjaye_stop(void)
{
    using namespace ninjaye;

    std::lock_guard<std::mutex> lock(g_state.lifecycle_mutex);
    if (!g_state.running.exchange(false))
    {
        return;
    }

    g_state.stop_requested = true;
    stop_input_capture();
    if (g_state.process_thread.joinable())
    {
        g_state.process_thread.join();
    }
    if (g_state.worker_thread.joinable())
    {
        g_state.worker_thread.join();
    }
    if (g_state.splash_thread.joinable())
    {
        g_state.splash_thread.join();
    }

    g_state.enrolled = false;
    reset_process_collection();
}

int32_t NINJAYE_CALL ninjaye_report_event(
    const char* type,
    const int32_t severity,
    const char* json_data)
{
    using namespace ninjaye;

    if (!g_state.running.load() ||
        type == nullptr ||
        *type == '\0')
    {
        return 0;
    }

    const char* value = json_data;
    if (value == nullptr || *value == '\0')
    {
        value = xorstr_("{}");
    }
    return send_event(type, severity, value) ? 1 : 0;
}

int32_t NINJAYE_CALL ninjaye_get_status(ninjaye_status* status)
{
    using namespace ninjaye;

    if (status == nullptr)
    {
        return 0;
    }

    std::memset(status, 0, sizeof(*status));
    status->running = g_state.running.load() ? 1 : 0;
    status->enrolled = g_state.enrolled.load() ? 1 : 0;
    strncpy_s(
        status->install_id,
        sizeof(status->install_id),
        g_state.install_id.c_str(),
        _TRUNCATE);
    strncpy_s(
        status->session_id,
        sizeof(status->session_id),
        g_state.session_id.c_str(),
        _TRUNCATE);
    status->events_sent = g_state.events_sent.load();
    status->reports_sent = g_state.reports_sent.load();
    status->detections_seen = g_state.detections_seen.load();
    status->files_attempted = g_state.files_attempted.load();
    status->files_sent = g_state.files_sent.load();
    status->last_http_status = g_state.last_http_status.load();

    std::lock_guard<std::mutex> lock(g_state.error_mutex);
    const std::wstring error = wide_from_utf8(g_state.last_error);
    wcsncpy_s(
        status->last_error,
        std::size(status->last_error),
        error.c_str(),
        _TRUNCATE);
    return 1;
}

const char* NINJAYE_CALL ninjaye_version(void)
{
    static const std::string version = xorstr_("1.0.0");
    return version.c_str();
}
}
