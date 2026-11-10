#ifndef NINJAYE_EXAMPLE_SERVER_H
#define NINJAYE_EXAMPLE_SERVER_H

#include <array>
#include <cstdint>
#include <string>

#pragma pack(push, 1)
struct gc_packet_aa
{
    uint8_t header = 0xAA;
    std::array<uint8_t, 8> opaque = {};
    uint32_t message = 0;
};
#pragma pack(pop)

static_assert(sizeof(gc_packet_aa) == 13);

class challenge_server
{
public:
    challenge_server(uint32_t profile_seed, uint32_t message_mask);

    static uint32_t file_crc32c(const std::wstring& path);

    gc_packet_aa create_challenge(
        uint32_t message,
        const std::array<uint8_t, 8>& opaque) const;

    uint32_t expected_response(uint32_t message) const;

    bool verify_response(
        const gc_packet_aa& request,
        const gc_packet_aa& reply) const;

private:
    uint32_t profile_seed_;
    uint32_t message_mask_;
};

#endif
