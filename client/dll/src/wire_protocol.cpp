#include "wire_protocol.h"

#include "json_utils.h"
#include "ninjaye_public_key.h"

#include <xorstr.hpp>
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstring>
#include <limits>
#include <span>
#include <string_view>

namespace ninjaye
{
namespace
{
constexpr size_t k_aes_key_size = 32;
constexpr size_t k_gcm_nonce_size = 12;
constexpr size_t k_gcm_tag_size = 16;
constexpr size_t k_rsa_ciphertext_size = 256;
constexpr size_t k_response_limit = 4 * 1024 * 1024;
constexpr NTSTATUS k_rsa_import_failed =
    static_cast<NTSTATUS>(0xE0000001u);
constexpr NTSTATUS k_rsa_encrypt_failed =
    static_cast<NTSTATUS>(0xE0000002u);

#pragma pack(push, 1)
struct rsa_public_blob
{
    BCRYPT_RSAKEY_BLOB header = {};
    uint8_t exponent[sizeof(k_rsa_public_exponent)] = {};
    uint8_t modulus[sizeof(k_rsa_public_modulus)] = {};
};
#pragma pack(pop)

struct mp_cursor
{
    const uint8_t* data = nullptr;
    size_t size = 0;
    size_t offset = 0;
};

bool append_bytes(
    std::vector<uint8_t>& output,
    const void* source,
    size_t size)
{
    const auto* bytes = static_cast<const uint8_t*>(source);
    output.insert(output.end(), bytes, bytes + size);
    return true;
}

bool append_byte(std::vector<uint8_t>& output, const uint8_t value)
{
    output.push_back(value);
    return true;
}

bool append_be16(std::vector<uint8_t>& output, const uint16_t value)
{
    output.push_back(static_cast<uint8_t>(value >> 8));
    output.push_back(static_cast<uint8_t>(value));
    return true;
}

bool append_be32(std::vector<uint8_t>& output, const uint32_t value)
{
    output.push_back(static_cast<uint8_t>(value >> 24));
    output.push_back(static_cast<uint8_t>(value >> 16));
    output.push_back(static_cast<uint8_t>(value >> 8));
    output.push_back(static_cast<uint8_t>(value));
    return true;
}

bool append_be64(std::vector<uint8_t>& output, const uint64_t value)
{
    output.push_back(static_cast<uint8_t>(value >> 56));
    output.push_back(static_cast<uint8_t>(value >> 48));
    output.push_back(static_cast<uint8_t>(value >> 40));
    output.push_back(static_cast<uint8_t>(value >> 32));
    output.push_back(static_cast<uint8_t>(value >> 24));
    output.push_back(static_cast<uint8_t>(value >> 16));
    output.push_back(static_cast<uint8_t>(value >> 8));
    output.push_back(static_cast<uint8_t>(value));
    return true;
}

bool append_mp_string(
    std::vector<uint8_t>& output,
    const std::string& value)
{
    if (value.size() <= 31)
    {
        append_byte(output, static_cast<uint8_t>(0xA0 | value.size()));
    }
    else if (value.size() <= 0xFF)
    {
        append_byte(output, 0xD9);
        append_byte(output, static_cast<uint8_t>(value.size()));
    }
    else if (value.size() <= 0xFFFF)
    {
        append_byte(output, 0xDA);
        append_be16(output, static_cast<uint16_t>(value.size()));
    }
    else
    {
        append_byte(output, 0xDB);
        append_be32(output, static_cast<uint32_t>(value.size()));
    }
    return append_bytes(output, value.data(), value.size());
}

bool append_mp_uint(
    std::vector<uint8_t>& output,
    const uint64_t value)
{
    if (value <= 0x7F)
    {
        return append_byte(output, static_cast<uint8_t>(value));
    }
    if (value <= 0xFF)
    {
        append_byte(output, 0xCC);
        return append_byte(output, static_cast<uint8_t>(value));
    }
    if (value <= 0xFFFF)
    {
        append_byte(output, 0xCD);
        return append_be16(output, static_cast<uint16_t>(value));
    }
    if (value <= 0xFFFFFFFFULL)
    {
        append_byte(output, 0xCE);
        return append_be32(output, static_cast<uint32_t>(value));
    }
    append_byte(output, 0xCF);
    return append_be64(output, value);
}

bool append_mp_map(
    std::vector<uint8_t>& output,
    const size_t count)
{
    if (count <= 15)
    {
        return append_byte(output, static_cast<uint8_t>(0x80 | count));
    }
    if (count <= 0xFFFF)
    {
        append_byte(output, 0xDE);
        return append_be16(output, static_cast<uint16_t>(count));
    }
    append_byte(output, 0xDF);
    return append_be32(output, static_cast<uint32_t>(count));
}

bool append_mp_array(
    std::vector<uint8_t>& output,
    const size_t count)
{
    if (count <= 15)
    {
        return append_byte(output, static_cast<uint8_t>(0x90 | count));
    }
    if (count <= 0xFFFF)
    {
        append_byte(output, 0xDC);
        return append_be16(output, static_cast<uint16_t>(count));
    }
    append_byte(output, 0xDD);
    return append_be32(output, static_cast<uint32_t>(count));
}

bool append_mp_pair(
    std::vector<uint8_t>& output,
    const std::string& key,
    const std::string& value)
{
    return append_mp_string(output, key) &&
        append_mp_string(output, value);
}

bool append_mp_pair(
    std::vector<uint8_t>& output,
    const std::string& key,
    const uint64_t value)
{
    return append_mp_string(output, key) &&
        append_mp_uint(output, value);
}

struct json_value
{
    enum class kind
    {
        null_value,
        boolean,
        integer,
        string,
        array,
        object,
    };

    kind type = kind::null_value;
    bool boolean_value = false;
    int64_t integer_value = 0;
    std::string string_value;
    std::vector<json_value> array_value;
    std::vector<std::pair<std::string, json_value>> object_value;
};

class json_parser
{
public:
    explicit json_parser(const std::string& source)
        : source_(source)
    {
    }

    bool parse(json_value& output)
    {
        skip_whitespace();
        if (!parse_value(output, 0))
        {
            return false;
        }
        skip_whitespace();
        return offset_ == source_.size();
    }

private:
    bool parse_value(json_value& output, const size_t depth)
    {
        if (depth > 64 || offset_ >= source_.size())
        {
            return false;
        }
        const char value = source_[offset_];
        if (value == '"')
        {
            output.type = json_value::kind::string;
            return parse_string(output.string_value);
        }
        if (value == '{')
        {
            return parse_object(output, depth);
        }
        if (value == '[')
        {
            return parse_array(output, depth);
        }
        if (consume_literal("null"))
        {
            output.type = json_value::kind::null_value;
            return true;
        }
        if (consume_literal("true"))
        {
            output.type = json_value::kind::boolean;
            output.boolean_value = true;
            return true;
        }
        if (consume_literal("false"))
        {
            output.type = json_value::kind::boolean;
            output.boolean_value = false;
            return true;
        }
        return parse_integer(output);
    }

    bool parse_object(json_value& output, const size_t depth)
    {
        output.type = json_value::kind::object;
        ++offset_;
        skip_whitespace();
        if (consume('}'))
        {
            return true;
        }

        while (offset_ < source_.size())
        {
            std::string key;
            if (!parse_string(key))
            {
                return false;
            }
            skip_whitespace();
            if (!consume(':'))
            {
                return false;
            }
            skip_whitespace();
            json_value value;
            if (!parse_value(value, depth + 1))
            {
                return false;
            }
            output.object_value.emplace_back(
                std::move(key),
                std::move(value));
            skip_whitespace();
            if (consume('}'))
            {
                return true;
            }
            if (!consume(','))
            {
                return false;
            }
            skip_whitespace();
        }
        return false;
    }

    bool parse_array(json_value& output, const size_t depth)
    {
        output.type = json_value::kind::array;
        ++offset_;
        skip_whitespace();
        if (consume(']'))
        {
            return true;
        }

        while (offset_ < source_.size())
        {
            json_value value;
            if (!parse_value(value, depth + 1))
            {
                return false;
            }
            output.array_value.push_back(std::move(value));
            skip_whitespace();
            if (consume(']'))
            {
                return true;
            }
            if (!consume(','))
            {
                return false;
            }
            skip_whitespace();
        }
        return false;
    }

    bool parse_string(std::string& output)
    {
        if (!consume('"'))
        {
            return false;
        }
        output.clear();
        while (offset_ < source_.size())
        {
            const unsigned char value =
                static_cast<unsigned char>(source_[offset_++]);
            if (value == '"')
            {
                return true;
            }
            if (value < 0x20)
            {
                return false;
            }
            if (value != '\\')
            {
                output.push_back(static_cast<char>(value));
                continue;
            }
            if (offset_ >= source_.size())
            {
                return false;
            }
            const char escape = source_[offset_++];
            switch (escape)
            {
            case '"': output.push_back('"'); break;
            case '\\': output.push_back('\\'); break;
            case '/': output.push_back('/'); break;
            case 'b': output.push_back('\b'); break;
            case 'f': output.push_back('\f'); break;
            case 'n': output.push_back('\n'); break;
            case 'r': output.push_back('\r'); break;
            case 't': output.push_back('\t'); break;
            case 'u':
            {
                uint32_t codepoint = 0;
                if (!parse_hex4(codepoint))
                {
                    return false;
                }
                if (codepoint >= 0xD800 && codepoint <= 0xDBFF)
                {
                    if (offset_ + 2 > source_.size() ||
                        source_[offset_] != '\\' ||
                        source_[offset_ + 1] != 'u')
                    {
                        return false;
                    }
                    offset_ += 2;
                    uint32_t low = 0;
                    if (!parse_hex4(low) ||
                        low < 0xDC00 ||
                        low > 0xDFFF)
                    {
                        return false;
                    }
                    codepoint =
                        0x10000u +
                        ((codepoint - 0xD800u) << 10) +
                        (low - 0xDC00u);
                }
                append_utf8(output, codepoint);
                break;
            }
            default:
                return false;
            }
        }
        return false;
    }

    bool parse_integer(json_value& output)
    {
        const size_t start = offset_;
        if (offset_ < source_.size() && source_[offset_] == '-')
        {
            ++offset_;
        }
        const size_t digits = offset_;
        while (offset_ < source_.size() &&
            source_[offset_] >= '0' &&
            source_[offset_] <= '9')
        {
            ++offset_;
        }
        if (digits == offset_)
        {
            return false;
        }
        if (offset_ < source_.size() &&
            (source_[offset_] == '.' ||
             source_[offset_] == 'e' ||
             source_[offset_] == 'E'))
        {
            return false;
        }
        int64_t value = 0;
        const auto result = std::from_chars(
            source_.data() + start,
            source_.data() + offset_,
            value);
        if (result.ec != std::errc())
        {
            return false;
        }
        output.type = json_value::kind::integer;
        output.integer_value = value;
        return true;
    }

    bool parse_hex4(uint32_t& output)
    {
        if (offset_ + 4 > source_.size())
        {
            return false;
        }
        output = 0;
        for (size_t index = 0; index < 4; ++index)
        {
            const char value = source_[offset_++];
            output <<= 4;
            if (value >= '0' && value <= '9')
                output |= static_cast<uint32_t>(value - '0');
            else if (value >= 'A' && value <= 'F')
                output |= static_cast<uint32_t>(value - 'A' + 10);
            else if (value >= 'a' && value <= 'f')
                output |= static_cast<uint32_t>(value - 'a' + 10);
            else
                return false;
        }
        return true;
    }

    static void append_utf8(
        std::string& output,
        const uint32_t codepoint)
    {
        if (codepoint <= 0x7Fu)
        {
            output.push_back(static_cast<char>(codepoint));
        }
        else if (codepoint <= 0x7FFu)
        {
            output.push_back(static_cast<char>(
                0xC0u | (codepoint >> 6)));
            output.push_back(static_cast<char>(
                0x80u | (codepoint & 0x3Fu)));
        }
        else if (codepoint <= 0xFFFFu)
        {
            output.push_back(static_cast<char>(
                0xE0u | (codepoint >> 12)));
            output.push_back(static_cast<char>(
                0x80u | ((codepoint >> 6) & 0x3Fu)));
            output.push_back(static_cast<char>(
                0x80u | (codepoint & 0x3Fu)));
        }
        else
        {
            output.push_back(static_cast<char>(
                0xF0u | (codepoint >> 18)));
            output.push_back(static_cast<char>(
                0x80u | ((codepoint >> 12) & 0x3Fu)));
            output.push_back(static_cast<char>(
                0x80u | ((codepoint >> 6) & 0x3Fu)));
            output.push_back(static_cast<char>(
                0x80u | (codepoint & 0x3Fu)));
        }
    }

    bool consume(const char expected)
    {
        if (offset_ < source_.size() &&
            source_[offset_] == expected)
        {
            ++offset_;
            return true;
        }
        return false;
    }

    bool consume_literal(const std::string_view value)
    {
        if (source_.size() - offset_ < value.size() ||
            source_.compare(
                offset_,
                value.size(),
                value) != 0)
        {
            return false;
        }
        offset_ += value.size();
        return true;
    }

    void skip_whitespace()
    {
        while (offset_ < source_.size() &&
            (source_[offset_] == ' ' ||
             source_[offset_] == '\t' ||
             source_[offset_] == '\r' ||
             source_[offset_] == '\n'))
        {
            ++offset_;
        }
    }

    const std::string& source_;
    size_t offset_ = 0;
};

bool append_mp_signed(
    std::vector<uint8_t>& output,
    const int64_t value)
{
    if (value >= 0)
    {
        return append_mp_uint(
            output,
            static_cast<uint64_t>(value));
    }
    if (value >= -32)
    {
        return append_byte(
            output,
            static_cast<uint8_t>(value));
    }
    if (value >= -128)
    {
        append_byte(output, 0xD0);
        return append_byte(
            output,
            static_cast<uint8_t>(value));
    }
    if (value >= -32768)
    {
        append_byte(output, 0xD1);
        return append_be16(
            output,
            static_cast<uint16_t>(value));
    }
    if (value >= std::numeric_limits<int32_t>::min())
    {
        append_byte(output, 0xD2);
        return append_be32(
            output,
            static_cast<uint32_t>(value));
    }
    append_byte(output, 0xD3);
    return append_be64(
        output,
        static_cast<uint64_t>(value));
}

bool append_mp_json_value(
    std::vector<uint8_t>& output,
    const json_value& value)
{
    switch (value.type)
    {
    case json_value::kind::null_value:
        return append_byte(output, 0xC0);
    case json_value::kind::boolean:
        return append_byte(
            output,
            value.boolean_value ? 0xC3 : 0xC2);
    case json_value::kind::integer:
        return append_mp_signed(
            output,
            value.integer_value);
    case json_value::kind::string:
        return append_mp_string(
            output,
            value.string_value);
    case json_value::kind::array:
        if (!append_mp_array(
                output,
                value.array_value.size()))
        {
            return false;
        }
        for (const json_value& child : value.array_value)
        {
            if (!append_mp_json_value(output, child))
                return false;
        }
        return true;
    case json_value::kind::object:
        if (!append_mp_map(
                output,
                value.object_value.size()))
        {
            return false;
        }
        for (const auto& pair : value.object_value)
        {
            if (!append_mp_string(output, pair.first) ||
                !append_mp_json_value(output, pair.second))
            {
                return false;
            }
        }
        return true;
    }
    return false;
}

bool append_mp_pair_json(
    std::vector<uint8_t>& output,
    const std::string& key,
    const std::string& json)
{
    json_value value;
    json_parser parser(json);
    return parser.parse(value) &&
        append_mp_string(output, key) &&
        append_mp_json_value(output, value);
}

bool read_byte(mp_cursor& cursor, uint8_t& value)
{
    if (cursor.offset >= cursor.size)
    {
        return false;
    }
    value = cursor.data[cursor.offset++];
    return true;
}

bool read_be(
    mp_cursor& cursor,
    const size_t width,
    uint64_t& value)
{
    if (width > 8 || width > cursor.size - cursor.offset)
    {
        return false;
    }
    value = 0;
    for (size_t index = 0; index < width; ++index)
    {
        value = (value << 8) | cursor.data[cursor.offset++];
    }
    return true;
}

bool read_mp_string(mp_cursor& cursor, std::string& value)
{
    uint8_t code = 0;
    if (!read_byte(cursor, code))
    {
        return false;
    }

    size_t length = 0;
    if ((code & 0xE0) == 0xA0)
    {
        length = code & 0x1F;
    }
    else if (code == 0xD9 || code == 0xDA || code == 0xDB)
    {
        uint64_t encoded_length = 0;
        const size_t width = code == 0xD9 ? 1 : (code == 0xDA ? 2 : 4);
        if (!read_be(cursor, width, encoded_length))
        {
            return false;
        }
        length = static_cast<size_t>(encoded_length);
    }
    else
    {
        return false;
    }

    if (length > cursor.size - cursor.offset)
    {
        return false;
    }
    value.assign(
        reinterpret_cast<const char*>(cursor.data + cursor.offset),
        length);
    cursor.offset += length;
    return true;
}

bool read_mp_number(mp_cursor& cursor, int64_t& value)
{
    uint8_t code = 0;
    if (!read_byte(cursor, code))
    {
        return false;
    }
    if (code <= 0x7F)
    {
        value = code;
        return true;
    }
    if (code >= 0xE0)
    {
        value = static_cast<int8_t>(code);
        return true;
    }

    uint64_t raw = 0;
    size_t width = 0;
    bool signed_value = false;
    switch (code)
    {
    case 0xCC:
        width = 1;
        break;
    case 0xCD:
        width = 2;
        break;
    case 0xCE:
        width = 4;
        break;
    case 0xCF:
        width = 8;
        break;
    case 0xD0:
        width = 1;
        signed_value = true;
        break;
    case 0xD1:
        width = 2;
        signed_value = true;
        break;
    case 0xD2:
        width = 4;
        signed_value = true;
        break;
    case 0xD3:
        width = 8;
        signed_value = true;
        break;
    default:
        return false;
    }

    if (!read_be(cursor, width, raw))
    {
        return false;
    }
    if (!signed_value)
    {
        value = raw > static_cast<uint64_t>(
            std::numeric_limits<int64_t>::max())
            ? std::numeric_limits<int64_t>::max()
            : static_cast<int64_t>(raw);
        return true;
    }

    if (width == 1)
    {
        value = static_cast<int8_t>(raw);
    }
    else if (width == 2)
    {
        value = static_cast<int16_t>(raw);
    }
    else if (width == 4)
    {
        value = static_cast<int32_t>(raw);
    }
    else
    {
        value = static_cast<int64_t>(raw);
    }
    return true;
}

bool read_mp_count(
    mp_cursor& cursor,
    const uint8_t marker,
    const uint8_t fixed_mask,
    const uint8_t fixed_base,
    const uint8_t marker16,
    const uint8_t marker32,
    size_t& count)
{
    uint8_t code = 0;
    if (!read_byte(cursor, code))
    {
        return false;
    }
    if ((code & fixed_mask) == fixed_base)
    {
        count = code & 0x0F;
        return true;
    }

    uint64_t value = 0;
    if (code == marker16)
    {
        if (!read_be(cursor, 2, value))
        {
            return false;
        }
    }
    else if (code == marker32)
    {
        if (!read_be(cursor, 4, value))
        {
            return false;
        }
    }
    else
    {
        static_cast<void>(marker);
        return false;
    }
    count = static_cast<size_t>(value);
    return count <= cursor.size;
}

bool skip_mp_value(mp_cursor& cursor, const uint32_t depth)
{
    if (depth > 64)
    {
        return false;
    }

    uint8_t code = 0;
    if (!read_byte(cursor, code))
    {
        return false;
    }
    if (code <= 0x7F || code >= 0xE0 ||
        code == 0xC0 || code == 0xC2 || code == 0xC3)
    {
        return true;
    }

    uint64_t length = 0;
    if (code == 0xCC || code == 0xD0)
    {
        return read_be(cursor, 1, length);
    }
    if (code == 0xCD || code == 0xD1)
    {
        return read_be(cursor, 2, length);
    }
    if (code == 0xCE || code == 0xD2 || code == 0xCA)
    {
        return read_be(cursor, 4, length);
    }
    if (code == 0xCF || code == 0xD3 || code == 0xCB)
    {
        return read_be(cursor, 8, length);
    }
    if ((code & 0xE0) == 0xA0)
    {
        length = code & 0x1F;
    }
    else if (code == 0xD9 || code == 0xC4)
    {
        if (!read_be(cursor, 1, length)) return false;
    }
    else if (code == 0xDA || code == 0xC5)
    {
        if (!read_be(cursor, 2, length)) return false;
    }
    else if (code == 0xDB || code == 0xC6)
    {
        if (!read_be(cursor, 4, length)) return false;
    }
    else if (code >= 0x90 && code <= 0x9F)
    {
        const size_t count = code & 0x0F;
        for (size_t index = 0; index < count; ++index)
        {
            if (!skip_mp_value(cursor, depth + 1)) return false;
        }
        return true;
    }
    else if (code >= 0x80 && code <= 0x8F)
    {
        const size_t count = code & 0x0F;
        for (size_t index = 0; index < count * 2; ++index)
        {
            if (!skip_mp_value(cursor, depth + 1)) return false;
        }
        return true;
    }
    else if (code == 0xDC || code == 0xDD)
    {
        if (!read_be(cursor, code == 0xDC ? 2 : 4, length))
        {
            return false;
        }
        for (size_t index = 0; index < static_cast<size_t>(length); ++index)
        {
            if (!skip_mp_value(cursor, depth + 1)) return false;
        }
        return true;
    }
    else if (code == 0xDE || code == 0xDF)
    {
        if (!read_be(cursor, code == 0xDE ? 2 : 4, length))
        {
            return false;
        }
        for (size_t index = 0;
            index < static_cast<size_t>(length) * 2;
            ++index)
        {
            if (!skip_mp_value(cursor, depth + 1)) return false;
        }
        return true;
    }
    else
    {
        return false;
    }
    return length <= cursor.size - cursor.offset &&
        ((cursor.offset += static_cast<size_t>(length)), true);
}

bool read_reserved2_rows(
    mp_cursor& cursor,
    const size_t count,
    std::vector<std::string>& keys)
{
    for (size_t index = 0; index < count; ++index)
    {
        size_t row_count = 0;
        if (!read_mp_count(cursor, 0x80, 0xF0, 0x80, 0xDE, 0xDF, row_count))
        {
            return false;
        }
        for (size_t row_index = 0; row_index < row_count; ++row_index)
        {
            std::string key;
            if (!read_mp_string(cursor, key))
            {
                return false;
            }
            if (key == xorstr_("String1"))
            {
                std::string value;
                if (!read_mp_string(cursor, value))
                {
                    return false;
                }
                keys.push_back(value);
            }
            else if (!skip_mp_value(cursor, 1))
            {
                return false;
            }
        }
    }
    return true;
}

bool contains_ascii(
    const std::string& body,
    const std::string& needle)
{
    return body.find(needle) != std::string::npos;
}

char ascii_lower(const char value)
{
    return value >= 'A' && value <= 'Z'
        ? static_cast<char>(value - 'A' + 'a')
        : value;
}

bool contains_ascii_case_insensitive(
    const std::string& body,
    const std::string& needle)
{
    if (needle.empty())
    {
        return true;
    }
    if (needle.size() > body.size())
    {
        return false;
    }
    for (size_t offset = 0;
        offset <= body.size() - needle.size();
        ++offset)
    {
        bool match = true;
        for (size_t index = 0; index < needle.size(); ++index)
        {
            if (ascii_lower(body[offset + index]) !=
                ascii_lower(needle[index]))
            {
                match = false;
                break;
            }
        }
        if (match)
        {
            return true;
        }
    }
    return false;
}

NTSTATUS aes_gcm_crypt(
    const std::span<const uint8_t, k_aes_key_size> key_bytes,
    const std::span<const uint8_t, k_gcm_nonce_size> nonce,
    const std::span<const uint8_t, k_gcm_tag_size> tag,
    const uint8_t* input,
    const size_t input_size,
    uint8_t* output,
    const bool encrypt)
{
    BCRYPT_ALG_HANDLE provider = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    PUCHAR object = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &provider,
        BCRYPT_AES_ALGORITHM,
        nullptr,
        0);
    if (status < 0)
    {
        return status;
    }

    status = BCryptSetProperty(
        provider,
        BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(
            const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
        sizeof(BCRYPT_CHAIN_MODE_GCM),
        0);
    if (status < 0)
    {
        BCryptCloseAlgorithmProvider(provider, 0);
        return status;
    }

    ULONG object_size = 0;
    ULONG result_size = 0;
    status = BCryptGetProperty(
        provider,
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&object_size),
        sizeof(object_size),
        &result_size,
        0);
    if (status < 0 || object_size == 0)
    {
        BCryptCloseAlgorithmProvider(provider, 0);
        return status;
    }

    object = static_cast<PUCHAR>(
        HeapAlloc(GetProcessHeap(), 0, object_size));
    if (object == nullptr)
    {
        BCryptCloseAlgorithmProvider(provider, 0);
        return static_cast<NTSTATUS>(0xC0000017u);
    }

    status = BCryptGenerateSymmetricKey(
        provider,
        &key,
        object,
        object_size,
        const_cast<PUCHAR>(key_bytes.data()),
        static_cast<ULONG>(key_bytes.size()),
        0);
    if (status >= 0)
    {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce = const_cast<PUCHAR>(nonce.data());
        info.cbNonce = static_cast<ULONG>(nonce.size());
        info.pbTag = const_cast<PUCHAR>(tag.data());
        info.cbTag = static_cast<ULONG>(tag.size());

        ULONG written = 0;
        status = encrypt
            ? BCryptEncrypt(
                key,
                const_cast<PUCHAR>(input),
                static_cast<ULONG>(input_size),
                &info,
                nullptr,
                0,
                output,
                static_cast<ULONG>(input_size),
                &written,
                0)
            : BCryptDecrypt(
                key,
                const_cast<PUCHAR>(input),
                static_cast<ULONG>(input_size),
                &info,
                nullptr,
                0,
                output,
                static_cast<ULONG>(input_size),
                &written,
                0);
        if (status >= 0 && written != input_size)
        {
            status = static_cast<NTSTATUS>(0xC0000206u);
        }
    }

    if (key != nullptr)
    {
        BCryptDestroyKey(key);
    }
    HeapFree(GetProcessHeap(), 0, object);
    BCryptCloseAlgorithmProvider(provider, 0);
    return status;
}

NTSTATUS rsa_oaep_encrypt(
    const std::span<const uint8_t, k_aes_key_size> plaintext,
    std::array<uint8_t, k_rsa_ciphertext_size>& ciphertext)
{
    rsa_public_blob blob = {};
    blob.header.Magic = BCRYPT_RSAPUBLIC_MAGIC;
    blob.header.BitLength = static_cast<ULONG>(
        std::size(k_rsa_public_modulus) * 8);
    blob.header.cbPublicExp = static_cast<ULONG>(
        std::size(k_rsa_public_exponent));
    blob.header.cbModulus = static_cast<ULONG>(
        std::size(k_rsa_public_modulus));
    std::copy(
        std::begin(k_rsa_public_exponent),
        std::end(k_rsa_public_exponent),
        std::begin(blob.exponent));
    std::copy(
        std::begin(k_rsa_public_modulus),
        std::end(k_rsa_public_modulus),
        std::begin(blob.modulus));

    BCRYPT_ALG_HANDLE provider = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &provider,
        BCRYPT_RSA_ALGORITHM,
        nullptr,
        0);
    if (status < 0)
    {
        return status;
    }

    status = BCryptImportKeyPair(
        provider,
        nullptr,
        BCRYPT_RSAPUBLIC_BLOB,
        &key,
        reinterpret_cast<PUCHAR>(&blob),
        sizeof(blob),
        0);
    if (status < 0)
    {
        BCryptCloseAlgorithmProvider(provider, 0);
        return k_rsa_import_failed;
    }

    BCRYPT_OAEP_PADDING_INFO padding = {};
    padding.pszAlgId = BCRYPT_SHA1_ALGORITHM;
    ULONG written = 0;
    status = BCryptEncrypt(
        key,
        const_cast<PUCHAR>(plaintext.data()),
        static_cast<ULONG>(plaintext.size()),
        &padding,
        nullptr,
        0,
        ciphertext.data(),
        static_cast<ULONG>(ciphertext.size()),
        &written,
        BCRYPT_PAD_OAEP);
    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(provider, 0);
    if (status < 0)
        return k_rsa_encrypt_failed;
    return written == ciphertext.size()
        ? static_cast<NTSTATUS>(0)
        : static_cast<NTSTATUS>(0xC0000206u);
}

bool encrypt_mpne(
    const std::vector<uint8_t>& plaintext,
    std::array<uint8_t, k_aes_key_size>& session_key,
    std::array<uint8_t, k_gcm_nonce_size>& gcm_nonce,
    std::array<uint8_t, k_gcm_tag_size>& gcm_tag,
    std::vector<uint8_t>& envelope,
    wire_error& error)
{
    error = wire_error::none;
    NTSTATUS status = BCryptGenRandom(
        nullptr,
        session_key.data(),
        static_cast<ULONG>(session_key.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0)
    {
        error = wire_error::crypto_random_failed;
        return false;
    }
    status = BCryptGenRandom(
        nullptr,
        gcm_nonce.data(),
        static_cast<ULONG>(gcm_nonce.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0)
    {
        error = wire_error::crypto_random_failed;
        return false;
    }

    std::vector<uint8_t> ciphertext(plaintext.size());
    status = aes_gcm_crypt(
        std::span<const uint8_t, k_aes_key_size>(session_key),
        std::span<const uint8_t, k_gcm_nonce_size>(gcm_nonce),
        std::span<const uint8_t, k_gcm_tag_size>(gcm_tag),
        plaintext.data(),
        plaintext.size(),
        ciphertext.data(),
        true);
    if (status < 0)
    {
        error = wire_error::crypto_aes_gcm_failed;
        return false;
    }

    std::array<uint8_t, k_rsa_ciphertext_size> wrapped_key = {};
    status = rsa_oaep_encrypt(
        std::span<const uint8_t, k_aes_key_size>(session_key),
        wrapped_key);
    if (status < 0)
    {
        error = wire_error::crypto_rsa_oaep_failed;
        return false;
    }

    envelope.clear();
    envelope.reserve(
        4 + gcm_nonce.size() + gcm_tag.size() +
        wrapped_key.size() + ciphertext.size());
    const char* mpne_magic = xorstr_("MPNE");
    append_bytes(envelope, mpne_magic, 4);
    append_bytes(envelope, gcm_nonce.data(), gcm_nonce.size());
    append_bytes(envelope, gcm_tag.data(), gcm_tag.size());
    append_bytes(envelope, wrapped_key.data(), wrapped_key.size());
    append_bytes(envelope, ciphertext.data(), ciphertext.size());
    return true;
}

void put_le16(uint8_t* output, const uint16_t value)
{
    output[0] = static_cast<uint8_t>(value);
    output[1] = static_cast<uint8_t>(value >> 8);
}

void put_le32(uint8_t* output, const uint32_t value)
{
    output[0] = static_cast<uint8_t>(value);
    output[1] = static_cast<uint8_t>(value >> 8);
    output[2] = static_cast<uint8_t>(value >> 16);
    output[3] = static_cast<uint8_t>(value >> 24);
}

void put_le64(uint8_t* output, const uint64_t value)
{
    put_le32(output, static_cast<uint32_t>(value));
    put_le32(output + 4, static_cast<uint32_t>(value >> 32));
}

std::string lowercase_hex(const uint8_t* bytes, const size_t size)
{
    static constexpr char alphabet[] = "0123456789abcdef";
    std::string output(size * 2, '\0');
    for (size_t index = 0; index < size; ++index)
    {
        output[index * 2] = alphabet[bytes[index] >> 4];
        output[index * 2 + 1] = alphabet[bytes[index] & 0x0F];
    }
    return output;
}

std::string random_boundary()
{
    std::array<uint8_t, 16> random = {};
    if (BCryptGenRandom(
            nullptr,
            random.data(),
            static_cast<ULONG>(random.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
    {
        const uint64_t tick = GetTickCount64();
        for (size_t index = 0; index < random.size(); ++index)
        {
            random[index] = static_cast<uint8_t>(
                (tick >> ((index % 8) * 8)) ^ (index * 0x3D));
        }
    }
    for (uint8_t& value : random)
    {
        value &= 0x0F;
    }
    return xorstr_("NinjAye-boundary-") + lowercase_hex(
        random.data(),
        random.size());
}

std::string format_dll_base(const uintptr_t dll_base)
{
    static constexpr char upper_hex[] = "0123456789ABCDEF";
    const uint32_t value = static_cast<uint32_t>(dll_base);
    std::string output(8, '0');
    for (size_t index = 0; index < output.size(); ++index)
    {
        const size_t shift = (output.size() - index - 1) * 4;
        output[index] = upper_hex[(value >> shift) & 0x0Fu];
    }
    return output;
}

std::string build_client_information_json(
    const report_wire_input& input)
{
    std::string output;
    output.reserve(640);
    output += xorstr_("{\"ReportType\":1");
    output += xorstr_(",\"DllVersion\":") +
        json_string(xorstr_("1.2.7.7"));
    output += xorstr_(",\"DllBase\":") +
        json_string(format_dll_base(input.dll_base));
    output += xorstr_(",\"DllImageHash\":") +
        json_string(input.dll_image_hash);
    output += xorstr_(",\"ClientId\":") +
        json_string(input.identity->client_id);
    output += xorstr_(",\"ClientIdV2\":") +
        json_string(input.identity->client_id_v2);
    output += xorstr_(",\"ClientIdV3_1\":") +
        json_string(input.identity->client_id_v3);
    output += xorstr_(",\"ClientIdV4\":") +
        json_string(input.identity->client_id_v4);
    output += xorstr_(",\"ClientIdV5\":") +
        json_string(input.identity->client_id_v5);
    output += xorstr_(",\"ServerId\":") +
        std::to_string(input.server_id);
    output += xorstr_(",\"ServerName\":") +
        json_string(input.profile_name);
    output += xorstr_(",\"Timestamp\":") +
        json_string(current_utc_iso8601());
    output += xorstr_(",\"ComputerName\":") +
        json_string(read_computer_name());
    output += xorstr_(",\"UserName\":") +
        json_string(read_user_name());
    output += "}";
    return output;
}

multipart_payload build_multipart(
    const std::vector<uint8_t>& payload,
    const std::string& filename)
{
    const std::string boundary = random_boundary();
    const std::string header =
        xorstr_("--") + boundary + xorstr_("\r\n") +
        xorstr_("Content-Disposition: form-data; name=\"file\"; filename=\"") +
        filename + xorstr_("\"\r\n") +
        xorstr_("Content-Type: application/octet-stream\r\n\r\n");
    const std::string trailer =
        xorstr_("\r\n--") + boundary + xorstr_("--\r\n");

    multipart_payload output;
    output.boundary = boundary;
    output.content_type =
        xorstr_("multipart/form-data; boundary=") + boundary;
    output.body.reserve(header.size() + payload.size() + trailer.size());
    append_bytes(output.body, header.data(), header.size());
    append_bytes(output.body, payload.data(), payload.size());
    append_bytes(output.body, trailer.data(), trailer.size());
    return output;
}

bool build_status_plaintext(
    const identity_snapshot& identity,
    const uint32_t server_id,
    const std::string& protocol_nonce,
    std::vector<uint8_t>& plaintext)
{
    plaintext.clear();
    plaintext.reserve(320);
    return append_mp_map(plaintext, 8) &&
        append_mp_pair(plaintext, xorstr_("ServerId"), server_id) &&
        append_mp_pair(plaintext, xorstr_("Nonce"), protocol_nonce) &&
        append_mp_pair(plaintext, xorstr_("DllVersion"), xorstr_("1.2.7.7")) &&
        append_mp_pair(plaintext, xorstr_("ClientId"), identity.client_id) &&
        append_mp_pair(
            plaintext,
            xorstr_("ClientIdV2"),
            identity.client_id_v2) &&
        append_mp_pair(
            plaintext,
            xorstr_("ClientIdV3"),
            identity.client_id_v3) &&
        append_mp_pair(
            plaintext,
            xorstr_("ClientIdV4"),
            identity.client_id_v4) &&
        append_mp_pair(
            plaintext,
            xorstr_("ClientIdV5"),
            identity.client_id_v5);
}
}

bool build_status_request(
    const identity_snapshot& identity,
    const uint32_t server_id,
    status_exchange_material& material,
    wire_error& error)
{
    error = wire_error::none;
    std::array<uint8_t, 16> nonce_bytes = {};
    NTSTATUS status = BCryptGenRandom(
        nullptr,
        nonce_bytes.data(),
        static_cast<ULONG>(nonce_bytes.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0)
    {
        error = wire_error::protocol_nonce_failed;
        return false;
    }
    static constexpr char upper_hex[] = "0123456789ABCDEF";
    material.protocol_nonce.assign(nonce_bytes.size() * 2, '\0');
    for (size_t index = 0; index < nonce_bytes.size(); ++index)
    {
        material.protocol_nonce[index * 2] = upper_hex[nonce_bytes[index] >> 4];
        material.protocol_nonce[index * 2 + 1] =
            upper_hex[nonce_bytes[index] & 0x0F];
    }

    std::vector<uint8_t> plaintext;
    if (!build_status_plaintext(
            identity,
            server_id,
            material.protocol_nonce,
            plaintext))
    {
        error = wire_error::messagepack_encode_failed;
        return false;
    }

    std::array<uint8_t, k_gcm_tag_size> tag = {};
    return encrypt_mpne(
        plaintext,
        material.session_key,
        material.gcm_nonce,
        tag,
        material.body,
        error);
}

bool consume_status_response(
    const http_response& response,
    const status_exchange_material& material,
    status_response_result& result)
{
    result = {};
    result.transport_ok = response.transport_ok;
    result.status_code = response.status_code;
    if (!response.transport_ok)
    {
        result.error = wire_error::transport_failed;
        return false;
    }

    const bool challenge_page =
        response.status_code == 403 ||
        contains_ascii_case_insensitive(
            response.content_type,
            xorstr_("text/html"));
    const bool challenge_body =
        contains_ascii(
            response.body,
            xorstr_("Verifying that you are not a robot...")) ||
        contains_ascii(response.body, xorstr_("__CF$cv$params")) ||
        contains_ascii(
            response.body,
            xorstr_("/cdn-cgi/challenge-platform/")) ||
        (!response.cf_ray.empty() &&
            contains_ascii(
                response.body,
                xorstr_(
                    "Access to this resource on the server is denied!")));
    const bool challenge = challenge_page && challenge_body;
    if (challenge)
    {
        result.challenge_detected = true;
        result.error = wire_error::challenge_detected;
        return false;
    }

    if (response.status_code != 200)
    {
        result.error = wire_error::response_http_status;
        return false;
    }
    if (response.body.size() <= 32)
    {
        result.error = wire_error::response_too_small;
        return false;
    }
    if (response.body.size() > k_response_limit)
    {
        result.error = wire_error::response_too_large;
        return false;
    }
    const char* mpne_magic = xorstr_("MPNE");
    if (std::memcmp(response.body.data(), mpne_magic, 4) != 0)
    {
        result.error = wire_error::response_not_mpne;
        return false;
    }

    const uint8_t* response_nonce = reinterpret_cast<const uint8_t*>(
        response.body.data() + 4);
    if (std::memcmp(
            response_nonce,
            material.gcm_nonce.data(),
            material.gcm_nonce.size()) == 0)
    {
        result.error = wire_error::response_nonce_reused;
        return false;
    }

    const uint8_t* response_tag = reinterpret_cast<const uint8_t*>(
        response.body.data() + 16);
    const uint8_t* ciphertext = reinterpret_cast<const uint8_t*>(
        response.body.data() + 32);
    const size_t ciphertext_size = response.body.size() - 32;
    std::vector<uint8_t> plaintext(ciphertext_size);
    const NTSTATUS decrypt_status = aes_gcm_crypt(
        std::span<const uint8_t, k_aes_key_size>(material.session_key),
        std::span<const uint8_t, k_gcm_nonce_size>(
            response_nonce,
            k_gcm_nonce_size),
        std::span<const uint8_t, k_gcm_tag_size>(
            response_tag,
            k_gcm_tag_size),
        ciphertext,
        ciphertext_size,
        plaintext.data(),
        false);
    if (decrypt_status < 0)
    {
        result.error = wire_error::response_decrypt_failed;
        return false;
    }

    mp_cursor cursor = {
        plaintext.data(),
        plaintext.size(),
        0,
    };
    size_t map_count = 0;
    if (!read_mp_count(
            cursor,
            0x80,
            0xF0,
            0x80,
            0xDE,
            0xDF,
            map_count))
    {
        result.error = wire_error::response_map_invalid;
        return false;
    }

    bool nonce_seen = false;
    bool nonce_matches = false;
    bool status_seen = false;
    int64_t status_value = 0;
    size_t blacklisted_count = 0;
    size_t reserved1_count = 0;
    bool reserved2_parsed = false;
    int64_t reserved50 = 0;
    for (size_t index = 0; index < map_count; ++index)
    {
        std::string key;
        if (!read_mp_string(cursor, key))
        {
            result.error = wire_error::response_key_invalid;
            return false;
        }

        if (key == xorstr_("Nonce"))
        {
            std::string value;
            if (!read_mp_string(cursor, value))
            {
                result.error = wire_error::response_nonce_invalid;
                return false;
            }
            nonce_seen = true;
            nonce_matches =
                value.size() == material.protocol_nonce.size() &&
                std::memcmp(
                    value.data(),
                    material.protocol_nonce.data(),
                    value.size()) == 0;
        }
        else if (key == xorstr_("Status"))
        {
            if (!read_mp_number(cursor, status_value))
            {
                result.error = wire_error::response_status_invalid;
                return false;
            }
            status_seen = true;
        }
        else if (key == xorstr_("BlacklistedMD5s") ||
                 key == xorstr_("Reserved1"))
        {
            size_t count = 0;
            if (!read_mp_count(
                    cursor,
                    0x90,
                    0xF0,
                    0x90,
                    0xDC,
                    0xDD,
                    count))
            {
                result.error = wire_error::response_array_invalid;
                return false;
            }
            (key == xorstr_("BlacklistedMD5s")
                ? blacklisted_count
                : reserved1_count) = count;
            for (size_t row = 0; row < count; ++row)
            {
                if (!skip_mp_value(cursor, 1))
                {
                    result.error = wire_error::response_array_row_invalid;
                    return false;
                }
            }
        }
        else if (key == xorstr_("Reserved2"))
        {
            size_t count = 0;
            if (!read_mp_count(
                    cursor,
                    0x90,
                    0xF0,
                    0x90,
                    0xDC,
                    0xDD,
                    count))
            {
                result.error = wire_error::response_reserved2_invalid;
                return false;
            }
            result.reserved2_keys.clear();
            if (!read_reserved2_rows(
                    cursor,
                    count,
                    result.reserved2_keys))
            {
                result.error = wire_error::response_reserved2_row_invalid;
                return false;
            }
            reserved2_parsed = true;
        }
        else if (key == xorstr_("Reserved50"))
        {
            if (!read_mp_number(cursor, reserved50))
            {
                result.error = wire_error::response_value_invalid;
                return false;
            }
        }
        else if (!skip_mp_value(cursor, 1))
        {
            result.error = wire_error::response_value_invalid;
            return false;
        }
    }

    if (!nonce_seen || !nonce_matches)
    {
        result.error = wire_error::response_nonce_mismatch;
        return false;
    }
    if (!status_seen)
    {
        result.error = wire_error::response_status_missing;
        return false;
    }
    if (blacklisted_count < 20)
    {
        result.error = wire_error::response_blacklist_short;
        return false;
    }
    if (reserved1_count < 20)
    {
        result.error = wire_error::response_reserved1_short;
        return false;
    }
    if (!reserved2_parsed)
    {
        result.reserved2_keys.clear();
    }

    result.status_value = status_value;
    result.event_mask =
        reserved50 >= 0
        ? static_cast<uint64_t>(reserved50)
        : 0;
    result.accepted = status_value == 0;
    if (!result.accepted)
    {
        result.error = wire_error::status_rejected;
    }
    return result.accepted;
}

std::vector<uint8_t> build_cache_event(
    const uint32_t argument0,
    const uint32_t argument1,
    const uint64_t argument2,
    const uint32_t process_id,
    const uint32_t server_id)
{
    FILETIME file_time = {};
    GetSystemTimeAsFileTime(&file_time);
    const uint64_t file_time_value =
        (static_cast<uint64_t>(file_time.dwHighDateTime) << 32) |
        file_time.dwLowDateTime;
    const uint64_t ticks = GetTickCount64();
    const uint32_t thread_id = GetCurrentThreadId();

    std::array<uint8_t, 60> record = {};
    const uint32_t seed =
        static_cast<uint32_t>(ticks) ^
        (process_id << 7) ^
        (thread_id << 13) ^
        0x6E31A5C7u;
    put_le32(record.data(), seed);
    uint8_t* header = record.data() + 4;
    put_le32(header + 0, 0x8D3C51A7u);
    put_le16(header + 4, 1);
    put_le16(header + 6, 56);
    put_le64(header + 8, file_time_value);
    put_le32(header + 16, process_id);
    put_le32(header + 20, thread_id);
    put_le64(header + 24, ticks);
    put_le32(header + 32, argument0);
    put_le64(header + 36, argument2);
    put_le32(header + 44, argument1);
    put_le32(header + 48, server_id);
    put_le32(header + 52, 0x01020707u);

    uint32_t state = seed != 0 ? seed : 0xA12F6C3Du;
    for (size_t index = 0; index < 56; ++index)
    {
        state = state * 1664525u + 1013904223u;
        header[index] ^= static_cast<uint8_t>(state >> 24);
    }
    return {
        record.begin(),
        record.end(),
    };
}

bool build_report_envelope(
    const report_wire_input& input,
    std::vector<uint8_t>& envelope,
    wire_error& error)
{
    error = wire_error::none;
    if (input.identity == nullptr)
    {
        error = wire_error::report_identity_missing;
        return false;
    }

    std::vector<uint8_t> plaintext;
    plaintext.reserve(
        512 + input.process_json.size() +
        input.telemetry_json.size() +
        input.detections_json.size());
    if (!append_mp_map(plaintext, 4) ||
        !append_mp_pair_json(
            plaintext,
            xorstr_("ClientInformation"),
            build_client_information_json(input)) ||
        !append_mp_pair_json(
            plaintext,
            xorstr_("ProcessInformation"),
            input.process_json) ||
        !append_mp_pair_json(
            plaintext,
            xorstr_("Telemetry"),
            input.telemetry_json) ||
        !append_mp_pair_json(
            plaintext,
            xorstr_("Detections"),
            input.detections_json))
    {
        error = wire_error::report_encode_failed;
        return false;
    }

    std::array<uint8_t, k_aes_key_size> session_key = {};
    std::array<uint8_t, k_gcm_nonce_size> gcm_nonce = {};
    std::array<uint8_t, k_gcm_tag_size> gcm_tag = {};
    return encrypt_mpne(
        plaintext,
        session_key,
        gcm_nonce,
        gcm_tag,
        envelope,
        error);
}

multipart_payload build_multipart_file(
    const std::vector<uint8_t>& payload)
{
    return build_multipart(payload, xorstr_("application"));
}

multipart_payload build_multipart_report(
    const std::vector<uint8_t>& envelope,
    const std::string& filename)
{
    return build_multipart(envelope, filename);
}

std::string random_report_filename()
{
    static constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::array<uint8_t, 36> random = {};
    if (BCryptGenRandom(
            nullptr,
            random.data(),
            static_cast<ULONG>(random.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
    {
        const uint64_t tick = GetTickCount64();
        for (size_t index = 0; index < random.size(); ++index)
        {
            random[index] = static_cast<uint8_t>(
                (tick >> ((index % 8) * 8)) ^ (index * 0x5B));
        }
    }

    std::string filename(random.size(), '\0');
    for (size_t index = 0; index < random.size(); ++index)
    {
        filename[index] = alphabet[random[index] % 36];
    }
    return filename;
}
}
