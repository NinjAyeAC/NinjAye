#include "server.h"

#include <array>
#include <fstream>

namespace
{
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
}

challenge_server::challenge_server(
    const uint32_t profile_seed,
    const uint32_t message_mask)
    : profile_seed_(profile_seed)
    , message_mask_(message_mask)
{
}

uint32_t challenge_server::file_crc32c(
    const std::wstring& path)
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

gc_packet_aa challenge_server::create_challenge(
    const uint32_t message,
    const std::array<uint8_t, 8>& opaque) const
{
    gc_packet_aa packet;
    packet.header = 0xAA;
    packet.opaque = opaque;
    packet.message = message;
    return packet;
}

uint32_t challenge_server::expected_response(
    const uint32_t message) const
{
    uint32_t value = profile_seed_;
    value += 0x7ED55D16u;
    value ^= 0xC761C23Cu;
    value += value << 12;
    value ^= value >> 19;
    value ^= message;
    value &= message_mask_;
    value += 0x165667B1u;
    value ^= 0x37994AB3u;
    value += value << 5;
    value ^= value >> 16;
    return value;
}

bool challenge_server::verify_response(
    const gc_packet_aa& request,
    const gc_packet_aa& reply) const
{
    return
        request.header == 0xAA &&
        reply.header == 0xAA &&
        request.opaque == reply.opaque &&
        reply.message == expected_response(request.message);
}
