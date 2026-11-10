#ifndef NINJAYE_INPUT_CAPTURE_H
#define NINJAYE_INPUT_CAPTURE_H

#include <cstdint>
#include <vector>

namespace ninjaye
{
struct keyboard_input_sample
{
    uint64_t ticks = 0;
    int64_t qpc = 0;
    uint64_t sequence = 0;
    uint64_t generation = 0;
    uint32_t code = 0;
    bool injected = false;
};

struct mouse_input_sample
{
    uint64_t ticks = 0;
    int64_t qpc = 0;
    uint64_t sequence = 0;
    uint64_t generation = 0;
    int32_t x = 0;
    int32_t y = 0;
    uint32_t move_count = 0;
    uint32_t channel = 0;
    double duration_ms = 0.0;
    bool injected = false;
    bool released = false;
    bool duration_valid = false;
    bool comparable = false;
    bool mixed_button_state = false;
};

struct input_capture_snapshot
{
    std::vector<keyboard_input_sample> keyboard;
    std::vector<mouse_input_sample> mouse;
    uint64_t maximum_keyboard_sequence = 0;
    uint64_t maximum_mouse_sequence = 0;
    uint64_t generation = 0;
    uint64_t started_tick = 0;
    int64_t qpc_frequency = 0;
    bool capture_ready = false;
};

bool start_input_capture();

void stop_input_capture();

input_capture_snapshot snapshot_input_capture();
}

#endif
