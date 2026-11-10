#include "detection_engine.h"

#include "detection_codes.h"
#include "detection_groups.h"
#include "detection_policy.h"
#include "identity_engine.h"
#include "input_capture.h"
#include "input_detection.h"
#include "json_utils.h"
#include "module_classifier.h"
#include "static_client_config.h"

#include <xorstr.hpp>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ninjaye
{
namespace
{
struct detection_item
{
    detection_id code_id;
    int severity = 0;
    int confidence = 0;
    std::string details;
    uint64_t policy_mask = 0;
    uint32_t policy_limit = 0;
    uint32_t policy_points = 0;
    bool group_result = false;
};

struct thread_history
{
    DWORD thread_id = 0;
    ULONGLONG first_seen = 0;
    ULONGLONG last_seen = 0;
    uint64_t generation = 0;
    uint32_t observations = 0;
    uint32_t maximum_suspend_count = 0;
    bool matching = false;
    bool confirmed_reported = false;
    ULONGLONG short_window_start = 0;
    uint32_t short_episodes = 0;
    ULONGLONG short_last_report = 0;
};

std::mutex g_thread_history_mutex;
std::unordered_map<DWORD, thread_history> g_thread_history;
std::mutex g_emission_mutex;
std::unordered_map<uint32_t, uint32_t> g_emission_counts;
uint64_t g_policy_score = 0;
ULONGLONG g_last_thread_summary_tick = 0;

int severity_for_points(const uint32_t points)
{
    if (points >= 60)
    {
        return 3;
    }
    if (points >= 20)
    {
        return 2;
    }
    return 1;
}

int confidence_for_points(const uint32_t points)
{
    if (points == 0)
    {
        return 50;
    }
    return static_cast<int>(std::min(points, 100u));
}

bool append_detection(
    std::vector<detection_item>& detections,
    const uint32_t code_id,
    const std::string& details,
    const bool group_result = false)
{
    const detection_policy policy =
        lookup_detection_policy(code_id);
    {
        std::lock_guard<std::mutex> lock(g_emission_mutex);
        uint32_t& count = g_emission_counts[code_id];
        if (policy.limit != 0 && count >= policy.limit)
        {
            return false;
        }
        ++count;
        if (code_id != static_cast<uint32_t>(
                detection_id::queued_report_task))
        {
            g_policy_score += policy.points;
        }
    }

    detections.push_back(
        {
            static_cast<detection_id>(code_id),
            severity_for_points(policy.points),
            confidence_for_points(policy.points),
            details,
            policy.mask,
            policy.limit,
            policy.points,
            group_result,
        });
    return true;
}

void append_cache_event(
    std::vector<raw_cache_event>& events,
    const uint32_t type,
    const uint32_t code,
    const uint64_t value)
{
    events.push_back({type, code, value});
}

void append_group_detections(
    std::vector<detection_item>& detections)
{
    std::unordered_set<uint32_t> observed;
    observed.reserve(detections.size() + 32);
    for (const detection_item& item : detections)
    {
        observed.insert(static_cast<uint32_t>(item.code_id));
    }

    bool changed = true;
    while (changed)
    {
        changed = false;
        for (const detection_group_rule& rule : k_detection_groups)
        {
            if (observed.contains(rule.result))
            {
                continue;
            }

            bool matched = true;
            for (uint32_t index = 0;
                index < rule.member_count;
                ++index)
            {
                if (!observed.contains(rule.members[index]))
                {
                    matched = false;
                    break;
                }
            }
            if (!matched)
            {
                continue;
            }

            std::ostringstream details;
            details << "{" << xorstr_("\"groupRule\":true,")
                << xorstr_("\"required\":[");
            for (uint32_t index = 0;
                index < rule.member_count;
                ++index)
            {
                if (index > 0)
                {
                    details << ",";
                }
                details << rule.members[index];
            }
            details << "]}";
            (void)append_detection(
                detections,
                rule.result,
                details.str(),
                true);
            observed.insert(rule.result);
            changed = true;
        }
    }
}

struct module_row
{
    std::string path;
    uintptr_t base = 0;
    uint32_t image_size = 0;
    module_trust trust;
};

std::string current_executable_path()
{
    std::vector<wchar_t> path(32768);
    const DWORD length = GetModuleFileNameW(
        nullptr,
        path.data(),
        static_cast<DWORD>(path.size()));
    return length == 0
        ? std::string()
        : utf8_from_wide(std::wstring(path.data(), length));
}

std::string current_module_path()
{
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&current_module_path),
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
        ? std::string()
        : utf8_from_wide(std::wstring(path.data(), length));
}

std::string basename(const std::string& path)
{
    const size_t separator = path.find_last_of("\\/");
    return separator == std::string::npos
        ? path
        : path.substr(separator + 1);
}

std::string os_version_string()
{
    using rtl_get_version_type = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
    const HMODULE ntdll = GetModuleHandleW(xorstr_(L"ntdll.dll"));
    const auto rtl_get_version = reinterpret_cast<rtl_get_version_type>(
        GetProcAddress(ntdll, xorstr_("RtlGetVersion")));
    RTL_OSVERSIONINFOW version = {};
    version.dwOSVersionInfoSize = sizeof(version);
    if (rtl_get_version != nullptr &&
        rtl_get_version(&version) == 0)
    {
        std::ostringstream output;
        output << version.dwMajorVersion << "."
            << version.dwMinorVersion << "."
            << version.dwBuildNumber;
        return output.str();
    }
    return "";
}

bool is_shadow_computer_name(const std::string& value)
{
    constexpr char prefix[] = "SHADOW-";
    constexpr size_t prefix_length = sizeof(prefix) - 1;
    if (value.size() != prefix_length + 8 ||
        value.compare(0, prefix_length, prefix) != 0)
    {
        return false;
    }
    for (size_t index = prefix_length;
        index < value.size();
        ++index)
    {
        const unsigned char character =
            static_cast<unsigned char>(value[index]);
        if (!((character >= 'A' && character <= 'Z') ||
            (character >= '0' && character <= '9')))
        {
            return false;
        }
    }
    return true;
}

DWORD process_thread_count(const DWORD process_id)
{
    DWORD count = 0;
    const HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPTHREAD,
        0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    THREADENTRY32 entry = {};
    entry.dwSize = sizeof(entry);
    if (Thread32First(snapshot, &entry))
    {
        do
        {
            if (entry.th32OwnerProcessID == process_id)
            {
                ++count;
            }
        } while (Thread32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return count;
}

std::vector<module_row> collect_current_modules()
{
    std::vector<module_row> modules;
    const HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return modules;
    }

    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry))
    {
        do
        {
            module_row row = {};
            row.path = utf8_from_wide(entry.szExePath);
            row.base = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
            row.image_size = entry.modBaseSize;
            row.trust = classify_module(row.path);
            modules.push_back(row);
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return modules;
}

void inspect_processes(std::string& processes_json)
{
    const HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS,
        0);
    std::vector<std::string> rows;
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snapshot, &entry))
        {
            do
            {
                const std::string name = utf8_from_wide(entry.szExeFile);
                std::ostringstream row;
                row << "{"
                    << xorstr_("\"pid\":") << entry.th32ProcessID << ","
                    << xorstr_("\"parentPid\":") << entry.th32ParentProcessID << ","
                    << xorstr_("\"name\":") << json_string(name)
                    << "}";
                rows.push_back(row.str());

            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }

    std::ostringstream output;
    output << "[";
    for (size_t index = 0; index < rows.size(); ++index)
    {
        if (index > 0)
        {
            output << ",";
        }
        output << rows[index];
    }
    output << "]";
    processes_json = output.str();
}

std::string build_modules_json(
    const std::vector<module_row>& modules)
{
    std::ostringstream output;
    output << "[";
    for (size_t index = 0; index < modules.size(); ++index)
    {
        if (index > 0)
        {
            output << ",";
        }

        std::ostringstream base;
        base << "0x" << std::hex << std::uppercase << modules[index].base;
        output << "{"
            << xorstr_("\"path\":") << json_string(modules[index].path) << ","
            << xorstr_("\"name\":") << json_string(basename(modules[index].path)) << ","
            << xorstr_("\"base\":") << json_string(base.str()) << ","
            << xorstr_("\"size\":") << std::dec << modules[index].image_size << ","
            << xorstr_("\"trusted\":")
            << (modules[index].trust.verified ? xorstr_("true") : xorstr_("false")) << ","
            << xorstr_("\"trustCode\":") << modules[index].trust.result_code << ","
            << xorstr_("\"signer\":") << json_string(modules[index].trust.signer)
            << "}";

    }
    output << "]";
    return output.str();
}

uint32_t saturating_u32(
    const uint64_t value,
    const uint32_t maximum)
{
    return static_cast<uint32_t>(
        std::min<uint64_t>(value, maximum));
}

uint64_t pack_thread_summary(
    const uint32_t count,
    const uint32_t positives,
    const uint32_t maximum,
    const std::array<uint32_t, 4>& indices,
    const uint32_t mode)
{
    uint64_t value =
        0xB000000000000000ull |
        saturating_u32(count, 255);
    for (uint32_t index = 0; index < 4; ++index)
    {
        value |= static_cast<uint64_t>(indices[index] & 0xFFu)
            << (8 * (index + 1));
    }
    value |= static_cast<uint64_t>(mode & 0x0Fu) << 40;
    value |= static_cast<uint64_t>(
        saturating_u32(positives, 255)) << 44;
    value |= static_cast<uint64_t>(
        saturating_u32(maximum, 255)) << 52;
    return value;
}

uint64_t pack_short_period(
    const uint32_t index,
    const uint32_t periods,
    const uint64_t window_ms,
    const uint64_t period_ms,
    const uint32_t observations)
{
    return 0xC000000000000000ull |
        static_cast<uint64_t>(index & 0xFFu) |
        (static_cast<uint64_t>(
            saturating_u32(periods, 255)) << 8) |
        (std::min<uint64_t>(
            (window_ms + 999u) / 1000u,
            255u) << 16) |
        (std::min<uint64_t>(
            (period_ms + 9u) / 10u,
            255u) << 24) |
        (static_cast<uint64_t>(
            std::min(observations, 15u)) << 32);
}

uint64_t pack_confirmed_thread(
    const uint32_t index,
    const uint64_t elapsed_ms,
    const uint32_t observations,
    const uint32_t suspend_count,
    const uint32_t flags,
    const uint32_t state,
    const uint32_t reason)
{
    return 0xA000000000000000ull |
        static_cast<uint64_t>(index & 0xFFu) |
        (std::min<uint64_t>(
            (elapsed_ms + 999u) / 1000u,
            255u) << 8) |
        (static_cast<uint64_t>(
            std::min(observations, 15u)) << 16) |
        (static_cast<uint64_t>(
            std::min(suspend_count, 15u)) << 20) |
        (static_cast<uint64_t>(reason & 0xFFu) << 24) |
        (static_cast<uint64_t>(state & 0x0Fu) << 32) |
        (static_cast<uint64_t>(flags & 0x0Fu) << 36);
}

std::string build_threads_json(
    const std::vector<module_row>& modules,
    std::vector<raw_cache_event>& cache_events)
{
    using nt_query_information_thread_type = NTSTATUS(NTAPI*)(
        HANDLE,
        ULONG,
        PVOID,
        ULONG,
        PULONG);
    const HMODULE ntdll = GetModuleHandleW(xorstr_(L"ntdll.dll"));
    const auto query_thread = reinterpret_cast<
        nt_query_information_thread_type>(
        GetProcAddress(ntdll, xorstr_("NtQueryInformationThread")));

    uint32_t matching_count = 0;
    uint32_t positive_suspend_count = 0;
    uint32_t maximum_suspend_count = 0;
    std::array<uint32_t, 4> matching_indices = {
        255,
        255,
        255,
        255,
    };
    const HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPTHREAD,
        0);
    std::vector<std::string> rows;
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 entry = {};
        entry.dwSize = sizeof(entry);
        if (Thread32First(snapshot, &entry))
        {
            do
            {
                if (entry.th32OwnerProcessID != GetCurrentProcessId())
                {
                    continue;
                }

                uintptr_t start_address = 0;
                bool queried = false;
                uint32_t thread_state = 0;
                uint32_t wait_reason = 0;
                uint32_t suspend_count = 0;
                if (query_thread != nullptr)
                {
                    const HANDLE thread = OpenThread(
                        THREAD_QUERY_INFORMATION |
                            THREAD_QUERY_LIMITED_INFORMATION,
                        FALSE,
                        entry.th32ThreadID);
                    if (thread != nullptr)
                    {
                        ULONG returned = 0;
                        queried = query_thread(
                            thread,
                            9,
                            &start_address,
                            sizeof(start_address),
                            &returned) >= 0;
                        std::array<uint8_t, 64> record = {};
                        ULONG system_returned = 0;
                        if (query_thread(
                                thread,
                                0x28,
                                record.data(),
                                static_cast<ULONG>(record.size()),
                                &system_returned) >= 0 &&
                            system_returned >= 0x3C)
                        {
                            std::memcpy(
                                &thread_state,
                                record.data() + 0x34,
                                sizeof(thread_state));
                            std::memcpy(
                                &wait_reason,
                                record.data() + 0x38,
                                sizeof(wait_reason));
                        }
                        ULONG suspend_returned = 0;
                        (void)query_thread(
                            thread,
                            0x23,
                            &suspend_count,
                            sizeof(suspend_count),
                            &suspend_returned);
                        CloseHandle(thread);
                    }
                }

                bool backed = false;
                if (queried)
                {
                    for (const module_row& module : modules)
                    {
                        if (start_address >= module.base &&
                            start_address < module.base + module.image_size)
                        {
                            backed = true;
                            break;
                        }
                    }
                }

                const bool matching =
                    entry.th32ThreadID != GetCurrentThreadId() &&
                    thread_state == 5 &&
                    (wait_reason == 5 || wait_reason == 12);
                if (matching)
                {
                    if (matching_count <
                        matching_indices.size())
                    {
                        matching_indices[matching_count] =
                            entry.th32ThreadID & 0xFFu;
                    }
                    ++matching_count;
                    if (suspend_count > 0)
                    {
                        ++positive_suspend_count;
                        maximum_suspend_count = std::max(
                            maximum_suspend_count,
                            suspend_count);
                    }
                }
                const ULONGLONG now = GetTickCount64();
                uint64_t generation = 0;
                uint64_t elapsed = 0;
                uint32_t observations = 0;
                {
                    std::lock_guard<std::mutex> lock(
                        g_thread_history_mutex);
                    thread_history& history =
                        g_thread_history[entry.th32ThreadID];
                    if (history.first_seen == 0 ||
                        now < history.last_seen ||
                        now - history.last_seen > 1500)
                    {
                        ++history.generation;
                        if (history.generation == 0)
                        {
                            ++history.generation;
                        }
                        history.thread_id = entry.th32ThreadID;
                        history.first_seen = now;
                        history.observations = 0;
                        history.maximum_suspend_count = 0;
                        history.confirmed_reported = false;
                    }
                    history.last_seen = now;
                    const bool previous_matching = history.matching;
                    history.matching = matching;
                    ++history.observations;
                    history.maximum_suspend_count = std::max(
                        history.maximum_suspend_count,
                        suspend_count);
                    generation = history.generation;
                    elapsed = now >= history.first_seen
                        ? now - history.first_seen
                        : 0;
                    observations = history.observations;

                    if (matching &&
                        elapsed >= 1500 &&
                        observations >= 2 &&
                        !history.confirmed_reported)
                    {
                        history.confirmed_reported = true;
                        append_cache_event(
                            cache_events,
                            0x10u,
                            static_cast<uint32_t>(
                                detection_id::thread_confirmed),
                            pack_confirmed_thread(
                                entry.th32ThreadID,
                                elapsed,
                                observations,
                                suspend_count,
                                suspend_count > 0 ? 3u : 2u,
                                thread_state,
                                wait_reason));
                    }
                    else if (!matching &&
                        previous_matching &&
                        elapsed < 1500 &&
                        observations > 0)
                    {
                        if (history.short_window_start == 0 ||
                            now < history.short_window_start ||
                            now - history.short_window_start > 60000)
                        {
                            history.short_window_start = now;
                            history.short_episodes = 0;
                        }
                        ++history.short_episodes;
                        if (history.short_episodes >= 4)
                        {
                            if (history.short_last_report == 0 ||
                                now < history.short_last_report ||
                                now - history.short_last_report >= 60000)
                            {
                                append_cache_event(
                                    cache_events,
                                    0x10u,
                                    static_cast<uint32_t>(
                                        detection_id::
                                            thread_short_period),
                                    pack_short_period(
                                        entry.th32ThreadID,
                                        history.short_episodes,
                                        now -
                                            history.short_window_start,
                                        elapsed,
                                        observations));
                                history.short_last_report = now;
                            }
                            history.short_episodes = 0;
                            history.short_window_start = now;
                        }
                    }
                }

                std::ostringstream address;
                address << "0x" << std::hex << std::uppercase << start_address;
                std::ostringstream row;
                row << "{"
                    << xorstr_("\"tid\":") << entry.th32ThreadID << ","
                    << xorstr_("\"queried\":")
                    << (queried ? xorstr_("true") : xorstr_("false")) << ","
                    << xorstr_("\"startAddress\":") << json_string(
                        queried ? address.str() : "")
                    << xorstr_(",\"backedByModule\":")
                    << (backed ? xorstr_("true") : xorstr_("false"))
                    << xorstr_(",\"state\":") << std::dec << thread_state
                    << xorstr_(",\"reason\":") << wait_reason
                    << xorstr_(",\"suspendCount\":") << suspend_count
                    << xorstr_(",\"matchingSuspendedState\":")
                    << (matching ? xorstr_("true") : xorstr_("false"))
                    << xorstr_(",\"generation\":") << generation
                    << "}";
                rows.push_back(row.str());
            } while (Thread32Next(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }

    {
        std::lock_guard<std::mutex> lock(g_thread_history_mutex);
        for (auto iterator = g_thread_history.begin();
            iterator != g_thread_history.end();)
        {
            const ULONGLONG now = GetTickCount64();
            if (iterator->second.last_seen != 0 &&
                now > iterator->second.last_seen &&
                now - iterator->second.last_seen > 300000)
            {
                iterator = g_thread_history.erase(iterator);
            }
            else
            {
                ++iterator;
            }
        }
    }

    if (matching_count >= 4)
    {
        const ULONGLONG now = GetTickCount64();
        bool emit_summary = false;
        {
            std::lock_guard<std::mutex> lock(g_thread_history_mutex);
            if (g_last_thread_summary_tick == 0 ||
                now < g_last_thread_summary_tick ||
                now - g_last_thread_summary_tick >= 60000)
            {
                g_last_thread_summary_tick = now;
                emit_summary = true;
            }
        }
        if (emit_summary)
        {
            append_cache_event(
                cache_events,
                0x10u,
                static_cast<uint32_t>(
                    detection_id::thread_summary),
                pack_thread_summary(
                    matching_count,
                    positive_suspend_count,
                    maximum_suspend_count,
                    matching_indices,
                    0u));
        }
    }

    std::ostringstream output;
    output << "[";
    for (size_t index = 0; index < rows.size(); ++index)
    {
        if (index > 0)
        {
            output << ",";
        }
        output << rows[index];
    }
    output << "]";
    return output.str();
}

uint32_t inspect_private_executable_regions(
    std::vector<detection_item>& detections,
    std::string& regions_json)
{
    uint32_t count = 0;
    std::ostringstream output;
    output << "[";
    bool first = true;
    SYSTEM_INFO system_info = {};
    GetSystemInfo(&system_info);
    uintptr_t address = reinterpret_cast<uintptr_t>(
        system_info.lpMinimumApplicationAddress);
    const uintptr_t maximum = reinterpret_cast<uintptr_t>(
        system_info.lpMaximumApplicationAddress);

    while (address < maximum)
    {
        MEMORY_BASIC_INFORMATION memory = {};
        if (VirtualQuery(
                reinterpret_cast<LPCVOID>(address),
                &memory,
                sizeof(memory)) == 0)
        {
            break;
        }

        const DWORD protection = memory.Protect & 0xFF;
        const bool executable =
            protection == PAGE_EXECUTE ||
            protection == PAGE_EXECUTE_READ ||
            protection == PAGE_EXECUTE_READWRITE ||
            protection == PAGE_EXECUTE_WRITECOPY;
        if (memory.State == MEM_COMMIT &&
            memory.Type == MEM_PRIVATE &&
            executable)
        {
            ++count;
            if (count <= 64)
            {
                if (!first)
                {
                    output << ",";
                }
                first = false;

                std::ostringstream details;
                details << "{"
                    << xorstr_("\"base\":") << reinterpret_cast<uintptr_t>(
                        memory.BaseAddress) << ","
                    << xorstr_("\"size\":") << memory.RegionSize << ","
                    << xorstr_("\"protection\":") << memory.Protect << ","
                    << xorstr_("\"type\":") << memory.Type
                    << "}";
                output << details.str();
                (void)append_detection(
                    detections,
                    static_cast<uint32_t>(
                        detection_id::private_region),
                    details.str());

                const DWORD writable_protection = memory.Protect & 0xFF;
                if (writable_protection == PAGE_EXECUTE_READWRITE ||
                    writable_protection == PAGE_EXECUTE_WRITECOPY)
                {
                    (void)append_detection(
                        detections,
                        static_cast<uint32_t>(
                            detection_id::writable_executable_region),
                        details.str());
                }
            }
        }

        const uintptr_t next = address + memory.RegionSize;
        if (next <= address)
        {
            break;
        }
        address = next;
    }
    output << "]";
    regions_json = output.str();
    return count;
}

uint32_t inspect_hardware_breakpoints(
    std::vector<detection_item>& detections,
    std::string& breakpoints_json)
{
    uint32_t count = 0;
    uintptr_t first_address = 0;
    uint32_t first_thread_id = 0;
    uint32_t first_slot = 0;
    std::ostringstream output;
    output << "[";
    bool first = true;

    const HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPTHREAD,
        0);
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 entry = {};
        entry.dwSize = sizeof(entry);
        if (Thread32First(snapshot, &entry))
        {
            do
            {
                if (entry.th32OwnerProcessID != GetCurrentProcessId() ||
                    entry.th32ThreadID == GetCurrentThreadId())
                {
                    continue;
                }

                const HANDLE thread = OpenThread(
                    THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                    FALSE,
                    entry.th32ThreadID);
                if (thread == nullptr)
                {
                    continue;
                }

                CONTEXT context = {};
                context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                const BOOL queried = GetThreadContext(thread, &context);
                CloseHandle(thread);
                if (!queried || context.Dr7 == 0)
                {
                    continue;
                }

                const DWORD_PTR addresses[4] =
                {
                    context.Dr0,
                    context.Dr1,
                    context.Dr2,
                    context.Dr3,
                };
                for (uint32_t slot = 0; slot < 4; ++slot)
                {
                    const DWORD_PTR enabled =
                        context.Dr7 & (3ull << (slot * 2));
                    const DWORD_PTR access =
                        (context.Dr7 >> (16 + slot * 4)) & 3;
                    const DWORD_PTR length =
                        (context.Dr7 >> (18 + slot * 4)) & 3;
                    if (enabled == 0 ||
                        access != 0 ||
                        length != 0)
                    {
                        continue;
                    }

                    ++count;
                    if (first_address == 0)
                    {
                        first_address = static_cast<uintptr_t>(
                            addresses[slot]);
                        first_thread_id = entry.th32ThreadID;
                        first_slot = slot;
                    }
                    if (!first)
                    {
                        output << ",";
                    }
                    first = false;

                    std::ostringstream details;
                    details << "{"
                        << xorstr_("\"address\":") << addresses[slot] << ","
                        << xorstr_("\"slot\":") << slot << ","
                        << xorstr_("\"tid\":") << entry.th32ThreadID << ","
                        << xorstr_("\"dr7\":") << context.Dr7
                        << "}";
                    output << details.str();
                    (void)append_detection(
                        detections,
                        static_cast<uint32_t>(
                            detection_id::execution_breakpoint),
                        details.str());
                }
            } while (Thread32Next(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }
    if (first_address != 0)
    {
        std::ostringstream details;
        details << "{"
            << xorstr_("\"address\":") << first_address << ","
            << xorstr_("\"slot\":") << first_slot << ","
            << xorstr_("\"tid\":") << first_thread_id
            << "}";
        (void)append_detection(
            detections,
            static_cast<uint32_t>(
                detection_id::recorded_breakpoint_address),
            details.str());
    }
    output << "]";
    breakpoints_json = output.str();
    return count;
}

std::string build_detections_json(
    const std::vector<detection_item>& detections)
{
    std::ostringstream output;
    output << "[";
    for (size_t index = 0; index < detections.size(); ++index)
    {
        if (index > 0)
        {
            output << ",";
        }
        const std::string& source_details =
            detections[index].details;
        const std::string detected_at =
            current_utc_iso8601();
        std::ostringstream heuristic;
        heuristic << std::hex << std::uppercase
            << static_cast<uint32_t>(
                detections[index].code_id);
        std::ostringstream flags;
        flags << std::hex << std::uppercase
            << std::setw(16) << std::setfill('0')
            << detections[index].policy_mask;
        std::ostringstream details;
        details << "{" << xorstr_("\"_policy\":{")
            << xorstr_("\"mask\":") << detections[index].policy_mask << ","
            << xorstr_("\"limit\":") << detections[index].policy_limit << ","
            << xorstr_("\"points\":") << detections[index].policy_points << ","
            << xorstr_("\"group\":")
            << (detections[index].group_result
                ? xorstr_("true")
                : xorstr_("false")) << "}";
        if (source_details.size() >= 2 &&
            source_details.front() == '{' &&
            source_details.back() == '}')
        {
            details << "," << source_details.substr(
                1,
                source_details.size() - 2);
        }
        else
        {
            details << "," << xorstr_("\"value\":")
                << json_string(source_details);
        }
        details << "}";

        output << "{"
            << xorstr_("\"Heur\":")
            << json_string(heuristic.str()) << ","
            << xorstr_("\"Points\":")
            << detections[index].policy_points << ","
            << xorstr_("\"Flags\":")
            << json_string(flags.str()) << ","
            << xorstr_("\"IsExperimental\":")
            << ((detections[index].policy_mask & 1u) != 0
                ? xorstr_("true")
                : xorstr_("false")) << ","
            << xorstr_("\"IsBeta\":")
            << ((detections[index].policy_mask & 2u) != 0
                ? xorstr_("true")
                : xorstr_("false")) << ","
            << xorstr_("\"Timestamp\":")
            << json_string(detected_at) << ","
            << xorstr_("\"String1\":")
            << json_string(source_details) << ","
            << xorstr_("\"Qword1\":0,")
            << xorstr_("\"codeId\":")
            << static_cast<uint32_t>(detections[index].code_id) << ","
            << xorstr_("\"severity\":") << detections[index].severity << ","
            << xorstr_("\"confidence\":") << detections[index].confidence << ","
            << xorstr_("\"policyMask\":") << detections[index].policy_mask << ","
            << xorstr_("\"policyLimit\":") << detections[index].policy_limit << ","
            << xorstr_("\"policyPoints\":") << detections[index].policy_points << ","
            << xorstr_("\"groupResult\":")
            << (detections[index].group_result
                ? xorstr_("true")
                : xorstr_("false")) << ","
            << xorstr_("\"detectedAt\":")
            << json_string(detected_at) << ","
            << xorstr_("\"details\":") << details.str()
            << "}";
    }
    output << "]";
    return output.str();
}
}

bool collect_detection_snapshot(
    const std::string& dll_path,
    const std::string& dll_sha256,
    const detection_runtime_context& runtime,
    detection_snapshot& snapshot,
    std::string& error)
{
    std::vector<detection_item> detections;
    std::vector<raw_cache_event> cache_events;

    if (!runtime.callback_registry_ready)
    {
        append_cache_event(
            cache_events,
            1u,
            static_cast<uint32_t>(
                detection_id::callback_registry_missing),
            0);
    }
    else if (runtime.callback_kind_count < 2)
    {
        append_cache_event(
            cache_events,
            2u,
            static_cast<uint32_t>(
                detection_id::callback_registry_incomplete),
            runtime.callback_kind_count);
    }

    if (runtime.status_transport_failed)
    {
        append_cache_event(
            cache_events,
            3u,
            static_cast<uint32_t>(
                detection_id::status_transport_failure),
            0);
    }
    if (runtime.status_transport_failed ||
        runtime.status_result_failed)
    {
        uint32_t bits = 0;
        if (runtime.status_result_failed)
        {
            bits |= 1;
        }
        if (runtime.status_transport_failed)
        {
            bits |= 2;
        }
        append_cache_event(
            cache_events,
            9u,
            static_cast<uint32_t>(
                detection_id::status_exchange_failure),
            bits);
    }
    const DWORD thread_count = process_thread_count(GetCurrentProcessId());
    const std::string computer_name = read_computer_name();
    if ((selected_static_profile().process_flags & 2ull) != 0 &&
        is_shadow_computer_name(computer_name))
    {
        std::ostringstream details;
        details << "{" << xorstr_("\"computerName\":")
            << json_string(computer_name) << "}";
        (void)append_detection(
            detections,
            static_cast<uint32_t>(detection_id::startup_worker),
            details.str());
    }

    std::string executable_regions_json;
    const uint32_t executable_regions =
        inspect_private_executable_regions(
            detections,
            executable_regions_json);
    std::string hardware_breakpoints_json;
    (void)inspect_hardware_breakpoints(
        detections,
        hardware_breakpoints_json);

    std::string processes_json;
    inspect_processes(processes_json);
    const std::vector<module_row> modules = collect_current_modules();
    const std::string modules_json = build_modules_json(modules);
    const std::string threads_json =
        build_threads_json(modules, cache_events);

    identity_snapshot identity = {};
    std::string identity_error;
    (void)collect_identity_snapshot(identity, identity_error);

    const input_capture_snapshot input_snapshot =
        snapshot_input_capture();
    const std::vector<input_detection_event> input_events =
        analyze_input_capture(
            input_snapshot,
            GetTickCount64());
    for (const input_detection_event& event : input_events)
    {
        (void)append_detection(
            detections,
            event.code_id,
            event.details);
    }

    MEMORYSTATUSEX memory = {};
    memory.dwLength = sizeof(memory);
    GlobalMemoryStatusEx(&memory);

    append_group_detections(detections);
    uint64_t policy_score = 0;
    {
        std::lock_guard<std::mutex> lock(g_emission_mutex);
        policy_score = g_policy_score;
    }
    if (policy_score >= 600)
    {
        (void)append_detection(
            detections,
            static_cast<uint32_t>(
                detection_id::queued_report_task),
            std::string(xorstr_("{\"score\":")) +
                std::to_string(policy_score) + "}");
    }
    append_group_detections(detections);
    const std::string detections_json =
        build_detections_json(detections);
    const std::string user_name = read_user_name();

    std::ostringstream process;
    process << "{"
        << xorstr_("\"pid\":") << GetCurrentProcessId() << ","
        << xorstr_("\"path\":") << json_string(current_executable_path()) << ","
        << xorstr_("\"dllPath\":") << json_string(dll_path) << ","
        << xorstr_("\"dllSha256\":") << json_string(dll_sha256) << ","
        << xorstr_("\"architecture\":")
#if defined(_WIN64)
        << xorstr_("\"x64\"")
#else
        << xorstr_("\"x86\"")
#endif
        << ","
        << xorstr_("\"modules\":") << modules_json << ","
        << xorstr_("\"processes\":") << processes_json << ","
        << xorstr_("\"threads\":") << threads_json << ","
        << xorstr_("\"privateExecutableRegions\":")
        << executable_regions_json << ","
        << xorstr_("\"hardwareBreakpoints\":")
        << hardware_breakpoints_json
        << xorstr_(",\"Heuristics\":")
        << detections_json
        << "}";

    std::ostringstream telemetry;
    telemetry << "{"
        << xorstr_("\"computerName\":") << json_string(computer_name) << ","
        << xorstr_("\"userName\":") << json_string(user_name) << ","
        << xorstr_("\"osVersion\":") << json_string(os_version_string()) << ","
        << xorstr_("\"memoryLoadPercent\":") << memory.dwMemoryLoad << ","
        << xorstr_("\"threadCount\":") << thread_count << ","
        << xorstr_("\"privateExecutableRegions\":") << executable_regions
        << "}";

    snapshot.cache_events = std::move(cache_events);
    snapshot.process_json = process.str();
    snapshot.telemetry_json = telemetry.str();
    snapshot.identity_json =
        std::string("{") +
        std::string(xorstr_("\"clientId\":")) +
            json_string(identity.client_id) + "," +
        xorstr_("\"clientIdV2\":") +
            json_string(identity.client_id_v2) + "," +
        xorstr_("\"clientIdV3\":") +
            json_string(identity.client_id_v3) + "," +
        xorstr_("\"clientIdV4\":") +
            json_string(identity.client_id_v4) + "," +
        xorstr_("\"clientIdV5\":") +
            json_string(identity.client_id_v5) + "," +
        xorstr_("\"sources\":") + identity.sources_json +
        "}";
    snapshot.detections_json = detections_json;
    snapshot.detection_count = static_cast<uint32_t>(detections.size());
    error.clear();
    return true;
}
}
