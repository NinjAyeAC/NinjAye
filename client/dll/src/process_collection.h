#ifndef NINJAYE_PROCESS_COLLECTION_H
#define NINJAYE_PROCESS_COLLECTION_H

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace ninjaye
{
using process_file_sink = void (*)(const std::wstring& path);

struct process_collection_config
{
    uint32_t current_process_id = 0;
    uint64_t profile_flags = 0;
    uint64_t event_mask = 0;
    const std::vector<std::string>* reserved2_keys = nullptr;
};

struct process_collection_stats
{
    uint32_t discovered = 0;
    uint32_t selected = 0;
    uint32_t filled = 0;
    uint32_t allowed = 0;
    uint32_t denied = 0;
    uint32_t file_candidates = 0;
};

process_collection_stats collect_process_files_once(
    const process_collection_config& config,
    process_file_sink sink);

void reset_process_collection();
}

#endif
