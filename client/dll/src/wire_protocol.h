#ifndef NINJAYE_WIRE_PROTOCOL_H
#define NINJAYE_WIRE_PROTOCOL_H

#include "http_client.h"
#include "identity_engine.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace ninjaye
{
enum class wire_error : uint32_t
{
    none = 0x00000000,
    invalid_argument = 0x00010001,
    crypto_random_failed = 0x00020001,
    crypto_aes_gcm_failed = 0x00020002,
    crypto_rsa_oaep_failed = 0x00020003,
    protocol_nonce_failed = 0x00030001,
    messagepack_encode_failed = 0x00030002,
    report_identity_missing = 0x00030003,
    report_encode_failed = 0x00030004,
    transport_failed = 0x00040001,
    challenge_detected = 0x00050001,
    response_http_status = 0x00050002,
    response_too_small = 0x00050003,
    response_too_large = 0x00050004,
    response_not_mpne = 0x00050005,
    response_nonce_reused = 0x00050006,
    response_decrypt_failed = 0x00050007,
    response_map_invalid = 0x00050008,
    response_key_invalid = 0x00050009,
    response_nonce_invalid = 0x0005000A,
    response_status_invalid = 0x0005000B,
    response_array_invalid = 0x0005000C,
    response_array_row_invalid = 0x0005000D,
    response_reserved2_invalid = 0x0005000E,
    response_reserved2_row_invalid = 0x0005000F,
    response_value_invalid = 0x00050010,
    response_nonce_mismatch = 0x00050011,
    response_status_missing = 0x00050012,
    response_blacklist_short = 0x00050013,
    response_reserved1_short = 0x00050014,
    status_rejected = 0x00050015,
};
static_assert(sizeof(wire_error) == sizeof(uint32_t));
static_assert(static_cast<uint32_t>(wire_error::none) == 0);

struct status_exchange_material
{
    std::array<uint8_t, 32> session_key = {};
    std::array<uint8_t, 12> gcm_nonce = {};
    std::string protocol_nonce;
    std::vector<uint8_t> body;
};

struct status_response_result
{
    bool transport_ok = false;
    bool challenge_detected = false;
    bool accepted = false;
    uint32_t status_code = 0;
    int64_t status_value = 0;
    uint64_t event_mask = 0;
    std::vector<std::string> reserved2_keys;
    wire_error error = wire_error::none;
};

struct report_wire_input
{
    const identity_snapshot* identity = nullptr;
    uint32_t server_id = 0;
    std::string profile_name;
    std::string dll_image_hash;
    uintptr_t dll_base = 0;
    std::string process_json;
    std::string telemetry_json;
    std::string detections_json;
};

struct multipart_payload
{
    std::string boundary;
    std::string content_type;
    std::vector<uint8_t> body;
};

bool build_status_request(
    const identity_snapshot& identity,
    uint32_t server_id,
    status_exchange_material& material,
    wire_error& error);

bool consume_status_response(
    const http_response& response,
    const status_exchange_material& material,
    status_response_result& result);

std::vector<uint8_t> build_cache_event(
    uint32_t argument0,
    uint32_t argument1,
    uint64_t argument2,
    uint32_t process_id,
    uint32_t server_id);

bool build_report_envelope(
    const report_wire_input& input,
    std::vector<uint8_t>& envelope,
    wire_error& error);

multipart_payload build_multipart_file(
    const std::vector<uint8_t>& payload);

multipart_payload build_multipart_report(
    const std::vector<uint8_t>& envelope,
    const std::string& filename);

std::string random_report_filename();
}

#endif
