#include "static_client_config.h"

#include <xorstr.hpp>

#include <mutex>

namespace ninjaye
{
namespace
{
std::mutex g_server_url_mutex;
std::wstring g_server_url;
}

std::wstring static_profile_name(const uint32_t server_id)
{
    if (server_id == k_static_profile.server_id)
    {
        return xorstr_(L"Mt2Test");
    }
    return {};
}

bool set_runtime_server_url(const std::wstring& server_address)
{
    if (server_address.empty() ||
        (server_address.rfind(L"https://", 0) != 0 &&
         server_address.rfind(L"http://", 0) != 0))
    {
        return false;
    }

    std::lock_guard<std::mutex> lock(g_server_url_mutex);
    g_server_url = server_address;
    return true;
}

std::wstring runtime_server_url()
{
    std::lock_guard<std::mutex> lock(g_server_url_mutex);
    return g_server_url;
}

std::wstring static_game_name()
{
    return xorstr_(L"metin2client");
}
}
