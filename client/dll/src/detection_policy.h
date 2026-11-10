#ifndef NINJAYE_DETECTION_POLICY_H
#define NINJAYE_DETECTION_POLICY_H

#include <cstdint>

namespace ninjaye
{
struct detection_policy
{
    uint64_t mask;
    uint32_t limit;
    uint32_t points;
};

constexpr detection_policy lookup_detection_policy(
    const uint32_t code_id) noexcept
{
    switch (code_id)
    {
    case 0x05u: return {0x4ull, 1u, 100u};
    case 0x19u: return {0x4ull, 1u, 100u};
    case 0x2Cu: return {0x2ull, 2u, 100u};
    case 0x46u: return {0x4ull, 1u, 100u};
    case 0x47u: return {0x4ull, 1u, 100u};
    case 0x48u: return {0x4ull, 1u, 100u};
    case 0x4Au: return {0x4ull, 1u, 100u};
    case 0x4Bu: return {0x4ull, 1u, 100u};
    case 0x4Cu: return {0x4ull, 1u, 100u};
    case 0x4Du: return {0x4ull, 1u, 100u};
    case 0x4Eu: return {0x4ull, 1u, 100u};
    case 0x50u: return {0x4ull, 1u, 100u};
    case 0x51u: return {0x4ull, 1u, 100u};
    case 0x52u: return {0x4ull, 1u, 100u};
    case 0x53u: return {0x4ull, 1u, 100u};
    case 0x54u: return {0x4ull, 1u, 100u};
    case 0x55u: return {0x4ull, 1u, 100u};
    case 0x5Fu: return {0x12ull, 1u, 100u};
    case 0x60u: return {0x12ull, 1u, 100u};
    case 0x61u: return {0x12ull, 1u, 100u};
    case 0x62u: return {0x2ull, 1u, 100u};
    case 0x63u: return {0x12ull, 1u, 100u};
    case 0x64u: return {0x12ull, 1u, 100u};
    case 0x65u: return {0x12ull, 1u, 100u};
    case 0x66u: return {0x12ull, 1u, 100u};
    case 0x67u: return {0x12ull, 1u, 100u};
    case 0x68u: return {0x12ull, 1u, 100u};
    case 0x69u: return {0x12ull, 1u, 100u};
    case 0x6Au: return {0x12ull, 1u, 100u};
    case 0x6Bu: return {0x12ull, 1u, 100u};
    case 0x6Cu: return {0x12ull, 1u, 100u};
    case 0x6Du: return {0x2ull, 1u, 100u};
    case 0x6Eu: return {0x12ull, 1u, 100u};
    case 0x6Fu: return {0x12ull, 1u, 100u};
    case 0x70u: return {0x12ull, 1u, 100u};
    case 0x71u: return {0x4ull, 1u, 100u};
    case 0x72u: return {0x4ull, 1u, 100u};
    case 0x73u: return {0x4ull, 1u, 100u};
    case 0x74u: return {0x4ull, 1u, 100u};
    case 0x75u: return {0x12ull, 1u, 100u};
    case 0x76u: return {0x12ull, 1u, 100u};
    case 0x77u: return {0x12ull, 1u, 100u};
    case 0x78u: return {0x12ull, 1u, 100u};
    case 0x79u: return {0x12ull, 1u, 100u};
    case 0x7Au: return {0x2ull, 1u, 100u};
    case 0x7Bu: return {0x4ull, 1u, 100u};
    case 0x7Cu: return {0x4ull, 1u, 100u};
    case 0x7Du: return {0x4ull, 1u, 100u};
    case 0x7Eu: return {0x4ull, 1u, 100u};
    case 0x7Fu: return {0x4ull, 1u, 100u};
    case 0x80u: return {0x2ull, 1u, 60u};
    case 0x81u: return {0x12ull, 1u, 100u};
    case 0x8Au: return {0x4ull, 1u, 100u};
    case 0x8Bu: return {0x4ull, 1u, 100u};
    case 0x8Cu: return {0x4ull, 1u, 100u};
    case 0x8Du: return {0x4ull, 1u, 100u};
    case 0x8Eu: return {0x4ull, 1u, 100u};
    case 0x8Fu: return {0x4ull, 1u, 100u};
    case 0x90u: return {0x4ull, 1u, 100u};
    case 0x91u: return {0x4ull, 1u, 100u};
    case 0x99u: return {0x4ull, 1u, 100u};
    case 0xB2u: return {0x2ull, 1u, 100u};
    case 0xB3u: return {0x2ull, 1u, 100u};
    case 0xB4u: return {0x2ull, 1u, 90u};
    case 0xB5u: return {0x2ull, 1u, 60u};
    case 0xB8u: return {0x2ull, 10u, 1u};
    case 0xB9u: return {0x2ull, 10u, 2u};
    case 0xBDu: return {0x2ull, 1u, 20u};
    case 0xC0u: return {0x2ull, 1u, 30u};
    case 0xC1u: return {0x2ull, 1u, 10u};
    case 0xC2u: return {0x2ull, 1u, 10u};
    case 0xC3u: return {0x2ull, 2u, 30u};
    case 0xC4u: return {0x1ull, 2u, 30u};
    case 0xC5u: return {0x1ull, 1u, 10u};
    case 0xC6u: return {0x1ull, 2u, 20u};
    case 0xC8u: return {0x1ull, 1u, 60u};
    case 0xC9u: return {0x2ull, 1u, 50u};
    case 0xD7u: return {0x1ull, 2u, 20u};
    case 0xD8u: return {0x1ull, 2u, 30u};
    case 0xD9u: return {0x1ull, 2u, 50u};
    case 0xDBu: return {0x2ull, 1u, 70u};
    case 0xDCu: return {0x2ull, 1u, 70u};
    case 0xDDu: return {0x1ull, 1u, 100u};
    case 0xDEu: return {0x1ull, 1u, 100u};
    case 0xDFu: return {0x1ull, 12u, 0u};
    case 0xE0u: return {0x2ull, 12u, 1u};
    case 0xE1u: return {0x2ull, 12u, 1u};
    case 0xE2u: return {0x2ull, 6u, 1u};
    case 0xE3u: return {0x2ull, 1u, 60u};
    case 0xE5u: return {0x2ull, 1u, 40u};
    case 0xE6u: return {0x2ull, 1u, 60u};
    case 0xE7u: return {0x2ull, 1u, 60u};
    case 0xE8u: return {0x2ull, 1u, 60u};
    case 0xE9u: return {0x2ull, 1u, 40u};
    case 0xEAu: return {0x2ull, 1u, 50u};
    case 0xEBu: return {0x2ull, 1u, 50u};
    case 0xECu: return {0x2ull, 1u, 20u};
    case 0xEDu: return {0x2ull, 1u, 100u};
    case 0xEEu: return {0x2ull, 1u, 100u};
    case 0xEFu: return {0x2ull, 1u, 100u};
    default: return {0u, 0u, 0u};
    }
}
}

#endif
