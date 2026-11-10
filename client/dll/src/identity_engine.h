#ifndef NINJAYE_IDENTITY_ENGINE_H
#define NINJAYE_IDENTITY_ENGINE_H

#include <string>

namespace ninjaye
{
struct identity_snapshot
{
    std::string client_id;
    std::string client_id_v2;
    std::string client_id_v3;
    std::string client_id_v4;
    std::string client_id_v5;
    std::string sources_json;
};

bool collect_identity_snapshot(
    identity_snapshot& snapshot,
    std::string& error);
}

#endif
