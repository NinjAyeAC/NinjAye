#ifndef NINJAYE_DETECTION_ENGINE_H
#define NINJAYE_DETECTION_ENGINE_H

#include <cstdint>
#include <string>
#include <vector>

namespace ninjaye
{
struct raw_cache_event
{
    uint32_t type = 0;
    uint32_t code = 0;
    uint64_t value = 0;
};

struct detection_runtime_context
{
    bool callback_registry_ready = true;
    uint32_t callback_kind_count = 2;
    bool status_transport_failed = false;
    bool status_result_failed = false;
    bool challenge_repeated = false;
    uint32_t challenge_repeat_count = 0;
    bool module_crc_mismatch = false;
    uint32_t module_crc = 0;
};

struct detection_snapshot
{
    std::string process_json;
    std::string telemetry_json;
    std::string identity_json;
    std::string detections_json;
    std::vector<raw_cache_event> cache_events;
    uint32_t detection_count = 0;
};

bool collect_detection_snapshot(
    const std::string& dll_path,
    const std::string& dll_sha256,
    const detection_runtime_context& runtime,
    detection_snapshot& snapshot,
    std::string& error);
}

#endif
