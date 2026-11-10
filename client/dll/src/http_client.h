#ifndef NINJAYE_HTTP_CLIENT_H
#define NINJAYE_HTTP_CLIENT_H

#include <cstdint>
#include <string>
#include <vector>

namespace ninjaye
{
enum class http_error : uint32_t
{
    none = 0x00000000,
    invalid_base_url = 0x00010001,
    open_failed = 0x00020001,
    connect_failed = 0x00030001,
    create_request_failed = 0x00040001,
    send_failed = 0x00050001,
    receive_failed = 0x00050002,
    query_status_failed = 0x00050003,
    query_data_failed = 0x00050004,
    read_failed = 0x00050005,
    response_too_large = 0x00050006,
};
static_assert(sizeof(http_error) == sizeof(uint32_t));
static_assert(static_cast<uint32_t>(http_error::none) == 0);

struct http_response
{
    bool transport_ok = false;
    uint32_t status_code = 0;
    std::string body;
    std::string content_type;
    std::string cf_ray;
    http_error error = http_error::none;
    uint32_t native_error = 0;
};

http_response http_post_bytes(
    const std::wstring& base_url,
    const std::string& path,
    const std::vector<uint8_t>& body,
    const std::string& bearer_token,
    const std::string& content_type);
}

#endif
