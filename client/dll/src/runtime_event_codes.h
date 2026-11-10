#ifndef NINJAYE_RUNTIME_EVENT_CODES_H
#define NINJAYE_RUNTIME_EVENT_CODES_H

#include <cstdint>
#include <string_view>

namespace ninjaye
{
constexpr uint32_t event_code_fnv1a_32(
    const std::string_view value) noexcept
{
    uint32_t hash = 2166136261u;
    for (const char character : value)
    {
        hash ^= static_cast<uint8_t>(character);
        hash *= 16777619u;
    }
    return hash;
}

inline constexpr uint32_t k_event_challenge_repeated_without_progress =
    event_code_fnv1a_32("challenge.repeated_without_progress");

inline constexpr uint32_t k_event_challenge_module_crc_mismatch =
    event_code_fnv1a_32("challenge.module_crc_mismatch");

static_assert(
    k_event_challenge_repeated_without_progress == 0x889DF279u);
static_assert(
    k_event_challenge_module_crc_mismatch == 0x14B5F4CEu);
}

#endif
