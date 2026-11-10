#include "bridge_runtime.h"

#include "../include/ninjaye.h"
#include "../include/ninjaye_bridge.h"
#include "identity_engine.h"
#include "json_utils.h"
#include "runtime_events.h"
#include "splash_window.h"
#include "static_client_config.h"

#include <xorstr.hpp>
#include <windows.h>
#include <winternl.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace ninjaye
{
namespace
{
struct semaphore_basic_information
{
    LONG current_count;
    LONG maximum_count;
};

using nt_query_semaphore_type = NTSTATUS(NTAPI*)(
    HANDLE,
    ULONG,
    PVOID,
    ULONG,
    PULONG);

std::atomic<bool> g_attach_thread_created = false;
std::atomic<bool> g_bridge_published = false;
std::once_flag g_integrity_once;
std::atomic<uint32_t> g_profile_seed = 0;
std::atomic<uint32_t> g_first_section_baseline = 0;
std::atomic<uint32_t> g_repeat_count = 0;
std::atomic<uint32_t> g_last_detection_count = 0;
std::atomic<uint32_t> g_last_report_count = 0;
std::atomic<bool> g_integrity_initialized = false;
std::atomic<bool> g_challenge_repeated = false;
std::atomic<uint32_t> g_challenge_repeat_count = 0;
std::atomic<bool> g_module_crc_mismatch = false;
std::atomic<uint32_t> g_module_crc = 0;
std::atomic<bool> g_splash_started = false;

uint32_t crc32c_update(
    uint32_t crc,
    const uint8_t* bytes,
    const size_t size)
{
    constexpr uint32_t polynomial = 0x82F63B78u;
    for (size_t index = 0; index < size; ++index)
    {
        crc ^= bytes[index];
        for (int bit = 0; bit < 8; ++bit)
        {
            crc = (crc >> 1) ^
                ((crc & 1u) != 0 ? polynomial : 0u);
        }
    }
    return crc;
}

uint32_t crc32c(
    const uint8_t* bytes,
    const size_t size)
{
    return ~crc32c_update(0xFFFFFFFFu, bytes, size);
}

std::wstring current_module_path()
{
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&bridge_runtime_attach),
            &module))
    {
        return {};
    }

    std::vector<wchar_t> path(32768);
    const DWORD length = GetModuleFileNameW(
        module,
        path.data(),
        static_cast<DWORD>(path.size()));
    return length == 0
        ? std::wstring()
        : std::wstring(path.data(), length);
}

uint32_t module_file_crc32c(const std::wstring& path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input)
    {
        return 0;
    }

    uint32_t crc = 0xFFFFFFFFu;
    std::array<uint8_t, 64 * 1024> buffer = {};
    while (input)
    {
        input.read(
            reinterpret_cast<char*>(buffer.data()),
            static_cast<std::streamsize>(buffer.size()));
        const std::streamsize read = input.gcount();
        if (read > 0)
        {
            crc = crc32c_update(
                crc,
                buffer.data(),
                static_cast<size_t>(read));
        }
    }
    return ~crc;
}

uint32_t first_section_crc32c()
{
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&bridge_runtime_attach),
            &module))
    {
        return 0;
    }

    const auto* base = reinterpret_cast<const uint8_t*>(module);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return 0;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->FileHeader.NumberOfSections == 0)
    {
        return 0;
    }
    const auto* section = IMAGE_FIRST_SECTION(nt);
    const uint8_t* start = base + section->VirtualAddress;
    return crc32c(start, section->Misc.VirtualSize);
}

std::wstring read_process_wide_string(
    const uintptr_t address,
    const size_t maximum_characters)
{
    if (address == 0 || maximum_characters == 0)
    {
        return {};
    }

    std::vector<wchar_t> buffer(maximum_characters, L'\0');
    SIZE_T read = 0;
    if (!ReadProcessMemory(
            GetCurrentProcess(),
            reinterpret_cast<LPCVOID>(address),
            buffer.data(),
            buffer.size() * sizeof(wchar_t),
            &read) ||
        read < sizeof(wchar_t))
    {
        return {};
    }

    buffer.back() = L'\0';
    return std::wstring(buffer.data());
}

void copy_identity_bytes(
    const std::string& identity,
    void* destination)
{
    if (destination == nullptr || identity.size() != 32)
    {
        return;
    }
    std::memcpy(destination, identity.data(), 32);
}

void NINJAYE_MESSAGE_CALL copy_machine_identity(void* destination)
{
    identity_snapshot snapshot = {};
    std::string error;
    if (collect_identity_snapshot(snapshot, error))
    {
        copy_identity_bytes(snapshot.client_id, destination);
    }
}

void NINJAYE_MESSAGE_CALL copy_cpu_disk_identity(void* destination)
{
    identity_snapshot snapshot = {};
    std::string error;
    if (collect_identity_snapshot(snapshot, error))
    {
        copy_identity_bytes(snapshot.client_id_v2, destination);
    }
}

void NINJAYE_MESSAGE_CALL copy_tpm_identity(void* destination)
{
    identity_snapshot snapshot = {};
    std::string error;
    if (collect_identity_snapshot(snapshot, error))
    {
        copy_identity_bytes(snapshot.client_id_v3, destination);
    }
}

void NINJAYE_MESSAGE_CALL copy_profile_list_identity(void* destination)
{
    identity_snapshot snapshot = {};
    std::string error;
    if (collect_identity_snapshot(snapshot, error))
    {
        copy_identity_bytes(snapshot.client_id_v4, destination);
    }
}

void NINJAYE_MESSAGE_CALL copy_file_id_identity(void* destination)
{
    identity_snapshot snapshot = {};
    std::string error;
    if (collect_identity_snapshot(snapshot, error))
    {
        copy_identity_bytes(snapshot.client_id_v5, destination);
    }
}

void initialize_integrity_state()
{
    std::call_once(
        g_integrity_once,
        []()
        {
            g_profile_seed = module_file_crc32c(current_module_path());
            g_first_section_baseline = first_section_crc32c();
            g_integrity_initialized = true;
        });
}

uint32_t NINJAYE_MESSAGE_CALL published_message(const uint32_t message)
{
    initialize_integrity_state();

    ninjaye_status status = {};
    ninjaye_get_status(&status);
    const uint32_t previous_detection = g_last_detection_count.exchange(
        static_cast<uint32_t>(status.detections_seen));
    const uint32_t previous_report = g_last_report_count.exchange(
        static_cast<uint32_t>(status.reports_sent));
    const bool state_changed =
        previous_detection != static_cast<uint32_t>(status.detections_seen) &&
        previous_report != static_cast<uint32_t>(status.reports_sent);
    if (state_changed)
    {
        g_repeat_count = 0;
        g_challenge_repeat_count = 0;
        g_challenge_repeated = false;
    }
    else if (++g_repeat_count >= 2)
    {
        g_challenge_repeat_count = g_repeat_count.load();
        g_challenge_repeated = true;
        (void)report_cache_record(
            6u,
            0x234u,
            0x100u);
#ifdef NINJAYE_CHALLENGE_ENFORCE
        TerminateProcess(GetCurrentProcess(), 0);
#endif
    }

    const uint32_t crc = first_section_crc32c();
    if (crc != g_first_section_baseline.load())
    {
        g_module_crc = crc;
        g_module_crc_mismatch = true;
        (void)report_cache_record(
            7u,
            0x244u,
            crc);
#ifdef NINJAYE_CHALLENGE_ENFORCE
        TerminateProcess(GetCurrentProcess(), 0);
#endif
    }

    uint32_t value = g_profile_seed.load();
    value += 0x7ED55D16u;
    value ^= 0xC761C23Cu;
    value += value << 12;
    value ^= value >> 19;
    value ^= message;
    value &= selected_static_profile().message_mask;
    value += 0x165667B1u;
    value ^= 0x37994AB3u;
    value += value << 5;
    value ^= value >> 16;
    return value;
}

DWORD WINAPI bridge_startup_thread(LPVOID)
{
    std::wstring semaphore_name = xorstr_(L"Local\\NinjAye") +
        std::to_wstring(GetCurrentProcessId());
    HANDLE semaphore = OpenSemaphoreW(
        SEMAPHORE_ALL_ACCESS,
        FALSE,
        semaphore_name.c_str());
    if (semaphore == nullptr)
    {
        return 1;
    }

    const HMODULE ntdll = GetModuleHandleW(xorstr_(L"ntdll.dll"));
    const auto query_semaphore = reinterpret_cast<nt_query_semaphore_type>(
        GetProcAddress(ntdll, xorstr_("NtQuerySemaphore")));
    semaphore_basic_information information = {};
    if (query_semaphore == nullptr ||
        query_semaphore(
            semaphore,
            0,
            &information,
            sizeof(information),
            nullptr) < 0)
    {
        CloseHandle(semaphore);
        return 1;
    }
    CloseHandle(semaphore);

    const uintptr_t config_address =
        static_cast<uint32_t>(information.maximum_count);
    ninjaye_client_config24 client_config = {};
    SIZE_T read = 0;
    if (!ReadProcessMemory(
            GetCurrentProcess(),
            reinterpret_cast<LPCVOID>(config_address),
            &client_config,
            sizeof(client_config),
            &read) ||
        read != sizeof(client_config) ||
        client_config.marker == nullptr ||
        client_config.callback == nullptr ||
        client_config.server_address == nullptr)
    {
        return 1;
    }

    uint32_t marker = 0;
    if (!ReadProcessMemory(
            GetCurrentProcess(),
            client_config.marker,
            &marker,
            sizeof(marker),
            &read) ||
        read != sizeof(marker) ||
        marker != selected_static_profile().marker)
    {
        return 1;
    }
    const static_profile* profile = find_static_profile(marker);
    if (profile == nullptr ||
        profile != &selected_static_profile())
    {
        return 1;
    }

    const std::wstring server_address = read_process_wide_string(
        reinterpret_cast<uintptr_t>(client_config.server_address),
        1024);
    if (!set_runtime_server_url(server_address))
    {
        return 1;
    }

#ifndef NINJAYE_DISABLE_SPLASH
    if (bridge_claim_splash())
    {
        std::thread(run_splash_window).detach();
    }
#endif

    client_config.callback(
        0,
        reinterpret_cast<const void*>(&published_message),
        0);
    client_config.callback(
        5,
        reinterpret_cast<const void*>(&copy_file_id_identity),
        0);
    client_config.callback(
        4,
        reinterpret_cast<const void*>(&copy_profile_list_identity),
        0);
    client_config.callback(
        3,
        reinterpret_cast<const void*>(&copy_tpm_identity),
        0);
    client_config.callback(
        2,
        reinterpret_cast<const void*>(&copy_cpu_disk_identity),
        0);
    client_config.callback(
        1,
        reinterpret_cast<const void*>(&copy_machine_identity),
        0);

    g_bridge_published = true;
    (void)ninjaye_start();
    return 0;
}
}

bool bridge_claim_splash()
{
    return !g_splash_started.exchange(true);
}

bridge_integrity_observation observe_bridge_integrity()
{
    bridge_integrity_observation observation;
    observation.callback_registry_ready =
        g_bridge_published.load();
    observation.callback_kind_count =
        observation.callback_registry_ready ? 2u : 0u;
    observation.challenge_repeated =
        g_challenge_repeated.load();
    observation.challenge_repeat_count =
        g_challenge_repeat_count.load();
    observation.module_crc_mismatch =
        g_module_crc_mismatch.load();
    observation.module_crc =
        g_module_crc.load();
    return observation;
}

void bridge_runtime_attach()
{
    if (g_attach_thread_created.exchange(true))
    {
        return;
    }
    const HANDLE thread = CreateThread(
        nullptr,
        0,
        bridge_startup_thread,
        nullptr,
        0,
        nullptr);
    if (thread != nullptr)
    {
        CloseHandle(thread);
    }
}

void bridge_runtime_detach()
{
    if (g_bridge_published.load())
    {
        ninjaye_stop();
    }
}
}
