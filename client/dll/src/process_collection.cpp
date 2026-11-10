#include "process_collection.h"

#include "json_utils.h"

#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <cwctype>
#include <map>
#include <set>
#include <string_view>
#include <vector>

namespace ninjaye
{
namespace
{
struct process_key
{
    uint32_t process_id = 0;
    uint32_t parent_process_id = 0;

    bool operator<(const process_key& other) const noexcept
    {
        return process_id < other.process_id ||
            (process_id == other.process_id &&
                parent_process_id < other.parent_process_id);
    }
};

struct process_record
{
    std::wstring image_name_lower;
    std::wstring image_path;
    std::string digest;
    bool ready = true;
    bool filled = false;
    bool access_denied = false;
    bool seen = false;
    bool alternate = false;
};

struct snapshot_row
{
    process_key key;
    std::wstring image_name_lower;
};

std::map<process_key, process_record> g_records;
std::set<uint32_t> g_suppressed_pids;

std::wstring lower_wide(std::wstring value)
{
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](const wchar_t character)
        {
            return static_cast<wchar_t>(
                std::towlower(character));
        });
    return value;
}

bool name_is(
    const std::wstring& value,
    const std::wstring_view expected)
{
    return value == expected;
}

bool name_in(
    const std::wstring& value,
    const std::initializer_list<std::wstring_view> names)
{
    return std::any_of(
        names.begin(),
        names.end(),
        [&](const std::wstring_view name)
        {
            return name_is(value, name);
        });
}

bool forced_name_match(
    const std::wstring& value,
    const uint64_t profile_flags)
{
    return
        ((profile_flags & 0x01ull) != 0 &&
            name_in(value, {L"pservice.exe", L"parsecd.exe"})) ||
        ((profile_flags & 0x04ull) != 0 &&
            name_in(value, {
                L"stardeskservice.exe",
                L"stardesk.exe",
            })) ||
        ((profile_flags & 0x08ull) != 0 &&
            name_is(value, L"deskin.exe")) ||
        ((profile_flags & 0x10ull) != 0 &&
            name_in(value, {
                L"avica.exe",
                L"avicacapturer.exe",
                L"avicaservice.exe",
                L"avicawatch.exe",
            })) ||
        ((profile_flags & 0x20ull) != 0 &&
            name_in(value, {
                L"idwinservice.exe",
                L"inputdirector.exe",
                L"inputdirectorsessionhelper.exe",
                L"idcmd.exe",
            }));
}

bool shell_breakout_name(const std::wstring& value)
{
    return name_in(
        value,
        {L"explorer.exe", L"sihost.exe"});
}

std::wstring query_process_image_path(const uint32_t process_id)
{
    const HANDLE process = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        process_id);
    if (process == nullptr)
    {
        return {};
    }

    std::vector<wchar_t> buffer(32768);
    DWORD size = static_cast<DWORD>(buffer.size());
    std::wstring output;
    if (QueryFullProcessImageNameW(
            process,
            0,
            buffer.data(),
            &size))
    {
        output.assign(buffer.data(), size);
    }
    CloseHandle(process);
    return output;
}

bool fill_process_record(
    const process_key& key,
    process_record& record)
{
    record.image_path = query_process_image_path(key.process_id);
    if (record.image_path.empty())
    {
        record.access_denied = true;
        record.ready = false;
        return false;
    }
    record.digest = md5_file_hex(record.image_path);
    record.ready = true;
    record.access_denied = false;
    return true;
}

bool reserved2_allows(
    const process_record& record,
    const process_collection_config& config)
{
    if (record.digest.size() != 32)
    {
        return true;
    }
    if (config.reserved2_keys == nullptr)
    {
        return false;
    }
    return std::find(
        config.reserved2_keys->begin(),
        config.reserved2_keys->end(),
        record.digest) != config.reserved2_keys->end();
}

bool derive_companion_path(
    const std::wstring& source,
    const wchar_t* extension,
    std::wstring& output)
{
    output.clear();
    if (source.size() < 4)
    {
        return false;
    }
    const std::wstring mapped = lower_wide(source);
    const std::wstring_view suffix(
        mapped.data() + mapped.size() - 4,
        4);
    if (suffix != L".exe" && suffix != L".dll")
    {
        return false;
    }
    output.assign(source.data(), source.size() - 4);
    output += extension;
    return true;
}

void submit_record(
    const process_key& key,
    process_record& record,
    const process_collection_config& config,
    const process_file_sink sink,
    process_collection_stats& stats)
{
    if (record.filled)
    {
        return;
    }
    record.filled = true;
    if (!fill_process_record(key, record))
    {
        return;
    }
    ++stats.filled;

    if (record.alternate || !record.ready)
    {
        return;
    }
    if (!reserved2_allows(record, config))
    {
        ++stats.denied;
        return;
    }
    ++stats.allowed;

    if (sink != nullptr && !record.image_path.empty())
    {
        sink(record.image_path);
        ++stats.file_candidates;
    }

    std::wstring companion;
    if (derive_companion_path(
            record.image_path,
            L".pdb",
            companion))
    {
        if (sink != nullptr)
        {
            sink(companion);
            ++stats.file_candidates;
        }
    }
    if (derive_companion_path(
            record.image_path,
            L".dll",
            companion))
    {
        if (sink != nullptr)
        {
            sink(companion);
            ++stats.file_candidates;
        }
    }
}

std::vector<snapshot_row> collect_snapshot(
    process_collection_stats& stats)
{
    std::vector<snapshot_row> rows;
    const HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS,
        0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return rows;
    }

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            snapshot_row row;
            row.key.process_id = entry.th32ProcessID;
            row.key.parent_process_id =
                entry.th32ParentProcessID;
            row.image_name_lower =
                lower_wide(entry.szExeFile);
            rows.push_back(row);
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    stats.discovered =
        static_cast<uint32_t>(rows.size());
    return rows;
}
}

process_collection_stats collect_process_files_once(
    const process_collection_config& config,
    const process_file_sink sink)
{
    process_collection_stats stats;
    std::vector<snapshot_row> rows = collect_snapshot(stats);
    if (rows.size() < 12)
    {
        return stats;
    }

    std::set<uint32_t> present_pids;
    for (const snapshot_row& row : rows)
    {
        present_pids.insert(row.key.process_id);
        auto [iterator, inserted] =
            g_records.try_emplace(row.key);
        process_record& record = iterator->second;
        if (inserted)
        {
            record.image_name_lower =
                row.image_name_lower;
            record.ready = true;
        }
        record.seen = false;
    }
    for (auto iterator = g_suppressed_pids.begin();
        iterator != g_suppressed_pids.end();)
    {
        if (*iterator != 0 &&
            !present_pids.contains(*iterator))
        {
            iterator = g_suppressed_pids.erase(iterator);
        }
        else
        {
            ++iterator;
        }
    }
    g_suppressed_pids.insert(0);

    for (const snapshot_row& row : rows)
    {
        auto iterator = g_records.find(row.key);
        if (iterator == g_records.end())
        {
            continue;
        }
        process_record& record = iterator->second;
        if (record.seen)
        {
            g_suppressed_pids.erase(row.key.process_id);
            continue;
        }
        record.seen = true;
        if (!record.ready)
        {
            continue;
        }

        if (name_is(
                record.image_name_lower,
                L"wininit.exe"))
        {
            g_suppressed_pids.insert(row.key.process_id);
            continue;
        }
        if (forced_name_match(
                record.image_name_lower,
                config.profile_flags))
        {
            ++stats.selected;
            submit_record(
                row.key,
                record,
                config,
                sink,
                stats);
            continue;
        }

        if (g_suppressed_pids.contains(
                row.key.parent_process_id))
        {
            const bool breakout =
                shell_breakout_name(
                    record.image_name_lower);
            if (!breakout ||
                (config.event_mask & 0x100ull) != 0)
            {
                g_suppressed_pids.insert(
                    row.key.process_id);
            }
            continue;
        }

        if (row.key.process_id !=
            config.current_process_id)
        {
            ++stats.selected;
            submit_record(
                row.key,
                record,
                config,
                sink,
                stats);
        }
    }
    return stats;
}

void reset_process_collection()
{
    g_records.clear();
    g_suppressed_pids.clear();
}
}
