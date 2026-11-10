#ifndef NINJAYE_RUNTIME_EVENTS_H
#define NINJAYE_RUNTIME_EVENTS_H

#include <cstdint>

namespace ninjaye
{
bool report_cache_record(
    uint32_t event_type,
    uint32_t event_code,
    uint64_t event_value);
}

#endif
