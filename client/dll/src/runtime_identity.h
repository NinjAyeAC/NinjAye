#ifndef NINJAYE_RUNTIME_IDENTITY_H
#define NINJAYE_RUNTIME_IDENTITY_H

#include <string>

namespace ninjaye
{
struct client_identity
{
    std::string base_url;
    std::string install_id;
    std::string token;
};

bool create_client_identity(
    const std::wstring& base_url,
    client_identity& identity,
    std::string& error);
}

#endif
