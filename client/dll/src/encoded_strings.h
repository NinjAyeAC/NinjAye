#ifndef NINJAYE_ENCODED_STRINGS_H
#define NINJAYE_ENCODED_STRINGS_H

#include <cstddef>
#include <cstdint>
#include <string>

namespace ninjaye
{
struct encoded_view
{
    uint8_t key;
    const uint8_t* bytes;
    std::size_t size;

    std::string decode() const
    {
        std::string result;
        result.reserve(size);
        for (std::size_t index = 0; index < size; ++index)
        {
            result.push_back(static_cast<char>(bytes[index] ^ key));
        }
        return result;
    }
};
}

#endif
