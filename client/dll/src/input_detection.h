#ifndef NINJAYE_INPUT_DETECTION_H
#define NINJAYE_INPUT_DETECTION_H

#include "input_capture.h"

#include <cstdint>
#include <string>
#include <vector>

namespace ninjaye
{
struct input_detection_event
{
    uint32_t code_id = 0;
    std::string details;
};

std::vector<input_detection_event> analyze_input_capture(
    const input_capture_snapshot& snapshot,
    uint64_t now_tick);

void reset_input_detection_state();
}

#endif
