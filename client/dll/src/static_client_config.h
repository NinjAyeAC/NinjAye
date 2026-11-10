#ifndef NINJAYE_STATIC_CLIENT_CONFIG_H
#define NINJAYE_STATIC_CLIENT_CONFIG_H

#include "../include/ninjaye_bridge.h"

#include <cstdint>
#include <string>

namespace ninjaye
{
struct static_profile
{
    uint32_t marker;
    uint32_t server_id;
    uint32_t message_mask;
    uint64_t process_flags;
};

inline constexpr static_profile k_static_profile =
{
    NINJAYE_PROFILE_MARKER,
    1u,
    0xFFFFFFFFu,
    0ull,
};

inline constexpr uint32_t k_status_interval_ms = 6u * 60u * 1000u;
inline constexpr uint32_t k_detection_interval_ms = 30000u;

static_assert(k_static_profile.marker == NINJAYE_PROFILE_MARKER);
static_assert(k_static_profile.server_id != 0u);

constexpr const static_profile* find_static_profile(
    const uint32_t marker) noexcept
{
    return marker == k_static_profile.marker
        ? &k_static_profile
        : nullptr;
}

constexpr const static_profile& selected_static_profile() noexcept
{
    return k_static_profile;
}

std::wstring static_profile_name(uint32_t server_id);

bool set_runtime_server_url(const std::wstring& server_address);

std::wstring runtime_server_url();

std::wstring static_game_name();
}

#endif
