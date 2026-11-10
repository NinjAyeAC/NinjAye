#include "runtime_identity.h"

#include "json_utils.h"

#include <xorstr.hpp>
#include <windows.h>
#include <bcrypt.h>

#include <array>

namespace ninjaye
{
namespace
{
std::string generate_runtime_token()
{
    std::array<unsigned char, 32> bytes = {};
    if (BCryptGenRandom(
            nullptr,
            bytes.data(),
            static_cast<ULONG>(bytes.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
    {
        return {};
    }

    static constexpr char alphabet[] = "0123456789ABCDEF";
    std::string token(bytes.size() * 2, '\0');
    for (size_t index = 0; index < bytes.size(); ++index)
    {
        token[index * 2] = alphabet[bytes[index] >> 4];
        token[index * 2 + 1] = alphabet[bytes[index] & 0x0F];
    }
    return token;
}
}

bool create_client_identity(
    const std::wstring& base_url,
    client_identity& identity,
    std::string& error)
{
    identity = {};
    identity.base_url = utf8_from_wide(base_url);
    identity.install_id = new_guid_string();
    if (identity.install_id.empty())
    {
        error = xorstr_("runtime_install_id_generation_failed");
        return false;
    }

    identity.token = generate_runtime_token();
    if (identity.token.empty())
    {
        identity.install_id.clear();
        error = xorstr_("local_token_generation_failed");
        return false;
    }

    error.clear();
    return true;
}
}
