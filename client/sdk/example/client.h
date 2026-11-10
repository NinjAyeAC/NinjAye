#ifndef NINJAYE_EXAMPLE_CLIENT_H
#define NINJAYE_EXAMPLE_CLIENT_H

#include "../include/ninjaye_sdk.h"
#include "server.h"

class challenge_client
{
public:
    explicit challenge_client(const ninjaye::client& protection);

    bool process_challenge(
        const gc_packet_aa& request,
        gc_packet_aa& reply) const;

private:
    const ninjaye::client& protection_;
};

#endif
