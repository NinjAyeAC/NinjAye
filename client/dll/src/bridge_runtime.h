#ifndef NINJAYE_BRIDGE_RUNTIME_H
#define NINJAYE_BRIDGE_RUNTIME_H

#include <cstdint>

namespace ninjaye
{
struct bridge_integrity_observation
{
    bool callback_registry_ready = false;
    uint32_t callback_kind_count = 0;
    bool challenge_repeated = false;
    uint32_t challenge_repeat_count = 0;
    bool module_crc_mismatch = false;
    uint32_t module_crc = 0;
};

void bridge_runtime_attach();

void bridge_runtime_detach();

bool bridge_claim_splash();

bridge_integrity_observation observe_bridge_integrity();
}

#endif
