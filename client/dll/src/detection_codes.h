#ifndef NINJAYE_DETECTION_CODES_H
#define NINJAYE_DETECTION_CODES_H

#include <cstdint>

namespace ninjaye
{
enum class detection_id : uint32_t
{
    callback_registry_missing = 0x17A,
    callback_registry_incomplete = 0x182,
    status_transport_failure = 0x1A0,
    thread_summary = 0x1ED,
    thread_short_period = 0x22D,
    challenge_repeated_without_progress = 0x234,
    module_crc_mismatch = 0x244,
    status_exchange_failure = 0x282,
    thread_confirmed = 0x2B1,
    process_handle = 0x555,
    private_region = 0x05,
    writable_executable_region = 0x19,
    process_report = 0x2C,
    queued_report_task = 0x81,
    startup_worker = 0x99,
    vtable_method = 0xB2,
    vtable_address = 0xB3,
    execution_breakpoint = 0xB4,
    recorded_breakpoint_address = 0xB5,
    process_record = 0xB8,
    process_detail = 0xB9,
    injected_mouse_input = 0xC1,
    injected_keyboard_input = 0xC2,
    low_interval_variation = 0xC3,
    continuous_input_window = 0xC4,
    repeated_input_sequence = 0xC5,
    low_input_code_mean = 0xC6,
    mixed_injected_input = 0xD7,
    keyboard_interval_distribution = 0xD8,
    injected_clear_divergence = 0xD9,
    channel_statistics = 0xDF,
    channel_periodic_input = 0xE0,
    channel_duration_statistics = 0xE1,
    short_duration_input = 0xE2,
    macro_composite = 0xE3,
};
}

#endif
