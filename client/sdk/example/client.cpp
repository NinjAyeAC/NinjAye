#include "client.h"

challenge_client::challenge_client(
    const ninjaye::client& protection)
    : protection_(protection)
{
}

bool challenge_client::process_challenge(
    const gc_packet_aa& request,
    gc_packet_aa& reply) const
{
    if (request.header != 0xAA)
    {
        return false;
    }

    reply = request;
    reply.message = 0;
    return protection_.resolve_challenge(
        request.message,
        reply.message);
}
