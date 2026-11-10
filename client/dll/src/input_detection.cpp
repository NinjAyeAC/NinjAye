#include "input_detection.h"

#include "json_utils.h"

#include <xorstr.hpp>

#include <algorithm>
#include <array>
#include <cmath>
#include <iomanip>
#include <limits>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ninjaye
{
namespace
{
constexpr uint64_t k_analysis_window_ms = 600000;
constexpr uint64_t k_capture_warmup_ms = 120000;

struct channel_state
{
    uint64_t last_plain = 0;
    uint64_t last_duration = 0;
    uint64_t last_df = 0;
    uint64_t last_e0 = 0;
    uint64_t last_e1 = 0;
    uint64_t last_e2 = 0;
    uint32_t df_count = 0;
    uint32_t e0_count = 0;
    uint32_t e1_count = 0;
    uint32_t e2_count = 0;
};

struct detection_state
{
    uint64_t generation = 0;
    uint64_t last_mouse = 0;
    uint64_t last_keyboard = 0;
    uint64_t last_left = 0;
    uint64_t last_injected_mouse = 0;
    uint64_t last_injected_keyboard = 0;
    uint64_t last_divergence = 0;
    std::array<uint64_t, 2> repeated_sequence = {};
    std::array<std::array<channel_state, 2>, 2> channels = {};
};

std::mutex g_state_mutex;
detection_state g_state;

double elapsed_milliseconds(
    const input_capture_snapshot& snapshot,
    const int64_t first,
    const int64_t last)
{
    if (first <= 0 ||
        last < first ||
        snapshot.qpc_frequency <= 0)
    {
        return -1.0;
    }
    return static_cast<double>(last - first) * 1000.0 /
        static_cast<double>(snapshot.qpc_frequency);
}

bool finite_elapsed_milliseconds(
    const input_capture_snapshot& snapshot,
    const int64_t first,
    const int64_t last,
    double& result)
{
    result = elapsed_milliseconds(snapshot, first, last);
    return std::isfinite(result) && result >= 0.0;
}

struct interval_statistics
{
    double variation = 0.0;
    double mean = 0.0;
    double deviation = 0.0;
};

bool calculate_interval_statistics(
    const std::vector<double>& values,
    const size_t minimum,
    interval_statistics& result)
{
    result = {};
    if (values.size() < minimum || values.empty())
    {
        return false;
    }

    double sum = 0.0;
    for (const double value : values)
    {
        sum += value;
    }
    result.mean = sum / static_cast<double>(values.size());
    if (!(result.mean > 0.0))
    {
        return false;
    }

    double squared = 0.0;
    for (const double value : values)
    {
        const double delta = value - result.mean;
        squared += delta * delta;
    }
    result.deviation = std::sqrt(
        squared / static_cast<double>(values.size()));
    result.variation = result.deviation / result.mean;
    return std::isfinite(result.variation) &&
        std::isfinite(result.mean) &&
        std::isfinite(result.deviation);
}

std::string build_details(
    const std::vector<uint64_t>& numbers,
    const std::vector<std::string>& strings)
{
    std::ostringstream output;
    output << "{" << xorstr_("\"numbers\":[");
    for (size_t index = 0; index < numbers.size(); ++index)
    {
        if (index > 0)
        {
            output << ",";
        }
        output << numbers[index];
    }
    output << "]," << xorstr_("\"strings\":[");
    for (size_t index = 0; index < strings.size(); ++index)
    {
        if (index > 0)
        {
            output << ",";
        }
        output << json_string(strings[index]);
    }
    output << "]}";
    return output.str();
}

void append_event(
    std::vector<input_detection_event>& events,
    const uint32_t code_id,
    const std::vector<uint64_t>& numbers = {},
    const std::vector<std::string>& strings = {})
{
    events.push_back({code_id, build_details(numbers, strings)});
}

std::vector<double> adjacent_intervals(
    const input_capture_snapshot& snapshot,
    const std::vector<keyboard_input_sample>& rows)
{
    std::vector<double> intervals;
    const keyboard_input_sample* previous = nullptr;
    for (const keyboard_input_sample& row : rows)
    {
        if (previous != nullptr)
        {
            double delta = 0.0;
            if (row.generation != previous->generation ||
                !finite_elapsed_milliseconds(
                    snapshot,
                    previous->qpc,
                    row.qpc,
                    delta))
            {
                return {};
            }
            intervals.push_back(delta);
        }
        previous = &row;
    }
    return intervals;
}

bool is_sequence_code(const uint32_t code)
{
    return (code >= 0x30u && code <= 0x39u) ||
        (code >= 0x41u && code <= 0x5Au) ||
        (code >= 0x70u && code <= 0x7Bu) ||
        code == 0x20u;
}

struct repetition_stats
{
    uint32_t count = 0;
    double mean = 0.0;
    double m2 = 0.0;

    void add(const double value)
    {
        ++count;
        const double delta = value - mean;
        mean += delta / static_cast<double>(count);
        m2 += (value - mean) * delta;
    }
};

struct repetition_candidate
{
    bool valid = false;
    size_t start = 0;
    uint32_t period = 0;
    uint32_t repeats = 0;
    uint32_t count = 0;
    uint32_t unique_codes = 0;
    double span_ms = 0.0;
    double max_adjacent_ms = 0.0;
    double mean_cycle_ms = 0.0;
    double max_variation = 0.0;
    std::array<double, 8> variation = {};
    uint64_t last_sequence = 0;
};

void consider_repetition(
    const input_capture_snapshot& snapshot,
    const std::vector<keyboard_input_sample>& rows,
    const size_t start,
    const uint32_t period,
    const uint32_t repeats,
    const double max_adjacent,
    const repetition_stats* stats,
    repetition_candidate& best)
{
    const uint32_t count = period * repeats;
    const size_t end = start + count;
    if (repeats < 20 || count < 48 || end > rows.size())
    {
        return;
    }

    const size_t group = rows[start].injected ? 1u : 0u;
    if (rows[end - 1].sequence <=
        g_state.repeated_sequence[group])
    {
        return;
    }

    double span_ms = 0.0;
    if (!finite_elapsed_milliseconds(
            snapshot,
            rows[start].qpc,
            rows[end - 1].qpc,
            span_ms) ||
        span_ms < 5000.0)
    {
        return;
    }

    repetition_candidate candidate;
    candidate.start = start;
    candidate.count = count;
    candidate.period = period;
    candidate.repeats = repeats;
    candidate.span_ms = span_ms;
    candidate.max_adjacent_ms = max_adjacent;
    candidate.last_sequence = rows[end - 1].sequence;

    for (uint32_t phase = 0; phase < period; ++phase)
    {
        bool duplicate = false;
        for (uint32_t previous = 0; previous < phase; ++previous)
        {
            if (rows[start + previous].code == rows[start + phase].code)
            {
                duplicate = true;
                break;
            }
        }
        if (!duplicate)
        {
            ++candidate.unique_codes;
        }

        const repetition_stats& phase_stats = stats[phase];
        if (phase_stats.count < 19 || phase_stats.mean < 50.0)
        {
            return;
        }
        const double variation = std::sqrt(
            std::max(
                0.0,
                phase_stats.m2 /
                    static_cast<double>(phase_stats.count))) /
            phase_stats.mean;
        if (!std::isfinite(variation) || !(variation < 0.06))
        {
            return;
        }
        candidate.variation[phase] = variation;
        candidate.max_variation =
            std::max(candidate.max_variation, variation);
        candidate.mean_cycle_ms +=
            phase_stats.mean / static_cast<double>(period);
    }

    candidate.valid = true;
    if (!best.valid ||
        candidate.count > best.count ||
        (candidate.count == best.count &&
            candidate.period < best.period) ||
        (candidate.count == best.count &&
            candidate.period == best.period &&
            candidate.last_sequence > best.last_sequence))
    {
        best = candidate;
    }
}

void find_repetition(
    const input_capture_snapshot& snapshot,
    const std::vector<keyboard_input_sample>& rows,
    const size_t first,
    const size_t end,
    repetition_candidate& best)
{
    for (size_t start = first; start < end; ++start)
    {
        for (uint32_t period = 1; period <= 8; ++period)
        {
            if (end - start < static_cast<size_t>(period) * 20 ||
                end - start < 48)
            {
                continue;
            }

            std::array<repetition_stats, 8> stats = {};
            double max_adjacent = 0.0;
            bool valid = true;
            for (uint32_t phase = 1; phase < period; ++phase)
            {
                double delta = 0.0;
                if (!finite_elapsed_milliseconds(
                        snapshot,
                        rows[start + phase - 1].qpc,
                        rows[start + phase].qpc,
                        delta))
                {
                    valid = false;
                    break;
                }
                max_adjacent = std::max(max_adjacent, delta);
            }
            if (!valid)
            {
                continue;
            }

            uint32_t repeats = 1;
            for (size_t next = start + period;
                next + period <= end;
                next += period)
            {
                bool matches = true;
                for (uint32_t phase = 0; phase < period; ++phase)
                {
                    if (rows[start + phase].code !=
                        rows[next + phase].code)
                    {
                        matches = false;
                        break;
                    }
                }
                if (!matches)
                {
                    break;
                }

                for (uint32_t phase = 0; phase < period; ++phase)
                {
                    double cycle = 0.0;
                    double adjacent = 0.0;
                    if (!finite_elapsed_milliseconds(
                            snapshot,
                            rows[next + phase - period].qpc,
                            rows[next + phase].qpc,
                            cycle) ||
                        !finite_elapsed_milliseconds(
                            snapshot,
                            rows[next + phase - 1].qpc,
                            rows[next + phase].qpc,
                            adjacent))
                    {
                        valid = false;
                        break;
                    }
                    stats[phase].add(cycle);
                    max_adjacent = std::max(max_adjacent, adjacent);
                }
                if (!valid)
                {
                    break;
                }
                ++repeats;
                consider_repetition(
                    snapshot,
                    rows,
                    start,
                    period,
                    repeats,
                    max_adjacent,
                    stats.data(),
                    best);
            }
        }
    }
}

void analyze_keyboard(
    const input_capture_snapshot& snapshot,
    const std::vector<keyboard_input_sample>& keys,
    std::vector<input_detection_event>& events)
{
    if (keys.empty())
    {
        return;
    }

    uint64_t maximum_injected = 0;
    for (const keyboard_input_sample& row : keys)
    {
        if (row.injected)
        {
            maximum_injected =
                std::max(maximum_injected, row.sequence);
        }
    }
    if (maximum_injected > g_state.last_injected_keyboard)
    {
        uint64_t count = 0;
        for (const keyboard_input_sample& row : keys)
        {
            if (row.injected)
            {
                ++count;
            }
        }
        append_event(
            events,
            0xC2u,
            {count, keys.size(), maximum_injected});
        g_state.last_injected_keyboard = maximum_injected;
    }

    const std::vector<double> all_intervals =
        adjacent_intervals(snapshot, keys);
    interval_statistics statistics;
    if (calculate_interval_statistics(
            all_intervals,
            40,
            statistics) &&
        statistics.variation < 0.35)
    {
        append_event(
            events,
            0xD8u,
            {
                static_cast<uint64_t>(
                    statistics.variation * 10000.0),
                static_cast<uint64_t>(statistics.mean),
                static_cast<uint64_t>(
                    statistics.deviation * 100.0),
                all_intervals.size(),
            });
    }

    std::vector<keyboard_input_sample> injected_rows;
    std::vector<keyboard_input_sample> clear_rows;
    for (const keyboard_input_sample& row : keys)
    {
        (row.injected ? injected_rows : clear_rows).push_back(row);
    }
    if (injected_rows.size() > 20 && clear_rows.size() > 20)
    {
        const int64_t from =
            std::max(injected_rows.front().qpc, clear_rows.front().qpc);
        const int64_t through =
            std::min(injected_rows.back().qpc, clear_rows.back().qpc);
        double span_ms = 0.0;
        if (finite_elapsed_milliseconds(
                snapshot,
                from,
                through,
                span_ms) &&
            span_ms >= 30000.0 &&
            injected_rows.back().sequence > g_state.last_divergence &&
            injected_rows.back().generation ==
                clear_rows.back().generation)
        {
            const std::vector<double> injected_intervals =
                adjacent_intervals(snapshot, injected_rows);
            const std::vector<double> clear_intervals =
                adjacent_intervals(snapshot, clear_rows);
            interval_statistics injected_statistics;
            interval_statistics clear_statistics;
            if (calculate_interval_statistics(
                    injected_intervals,
                    20,
                    injected_statistics) &&
                calculate_interval_statistics(
                    clear_intervals,
                    20,
                    clear_statistics) &&
                injected_statistics.variation < 0.06 &&
                clear_statistics.variation > 0.25)
            {
                append_event(
                    events,
                    0xD9u,
                    {
                        static_cast<uint64_t>(
                            injected_statistics.variation * 10000.0),
                        static_cast<uint64_t>(
                            clear_statistics.variation * 10000.0),
                        static_cast<uint64_t>(
                            injected_statistics.mean),
                        injected_intervals.size(),
                        2,
                        static_cast<uint64_t>(span_ms * 100.0),
                        clear_intervals.size(),
                        static_cast<uint64_t>(
                            clear_statistics.mean * 100.0),
                        static_cast<uint64_t>(
                            injected_statistics.deviation * 100.0),
                        static_cast<uint64_t>(
                            clear_statistics.deviation * 100.0),
                        injected_rows.back().generation,
                        injected_rows.back().sequence,
                        clear_rows.back().sequence,
                        static_cast<uint64_t>(from),
                        static_cast<uint64_t>(through),
                    });
                g_state.last_divergence =
                    injected_rows.back().sequence;
            }
        }
    }

    size_t eligible_count = 0;
    for (const keyboard_input_sample& row : keys)
    {
        if (is_sequence_code(row.code))
        {
            ++eligible_count;
        }
    }

    std::array<repetition_candidate, 2> best;
    bool active = false;
    size_t start = 0;
    for (size_t index = 0; index <= keys.size(); ++index)
    {
        const bool eligible =
            index < keys.size() &&
            is_sequence_code(keys[index].code);
        bool split = !eligible;
        if (eligible && active)
        {
            double delta = 0.0;
            split =
                keys[index].injected != keys[index - 1].injected ||
                keys[index].generation != keys[index - 1].generation ||
                !finite_elapsed_milliseconds(
                    snapshot,
                    keys[index - 1].qpc,
                    keys[index].qpc,
                    delta) ||
                delta >= 3000.0;
        }
        if (active && split)
        {
            find_repetition(
                snapshot,
                keys,
                start,
                index,
                best[keys[start].injected ? 1u : 0u]);
            active = false;
        }
        if (eligible && !active)
        {
            start = index;
            active = true;
        }
    }

    constexpr char hex[] = "0123456789ABCDEF";
    for (uint32_t group = 0; group < 2; ++group)
    {
        const repetition_candidate& candidate = best[group];
        if (!candidate.valid)
        {
            continue;
        }

        std::vector<uint64_t> numbers = {
            candidate.repeats - 1u,
            candidate.period,
            eligible_count,
            256,
            candidate.unique_codes,
            static_cast<uint64_t>(
                candidate.max_variation * 10000.0),
            2u,
            group,
            static_cast<uint64_t>(candidate.span_ms * 100.0),
            static_cast<uint64_t>(
                candidate.max_adjacent_ms * 100.0),
            static_cast<uint64_t>(
                candidate.mean_cycle_ms * 100.0),
            candidate.repeats - 1u,
            candidate.count,
            keys[candidate.start].generation,
        };
        for (uint32_t phase = 0; phase < candidate.period; ++phase)
        {
            numbers.push_back(static_cast<uint64_t>(
                candidate.variation[phase] * 10000.0));
        }

        std::string codes;
        for (uint32_t phase = 0; phase < candidate.period; ++phase)
        {
            if (phase > 0)
            {
                codes.push_back(' ');
            }
            const uint32_t value =
                keys[candidate.start + phase].code & 0xFFu;
            codes.push_back(hex[value >> 4]);
            codes.push_back(hex[value & 0x0Fu]);
        }
        append_event(events, 0xC5u, numbers, {codes});
        g_state.repeated_sequence[group] =
            candidate.last_sequence;
    }
}

bool analyze_left_variation(
    const input_capture_snapshot& snapshot,
    const std::vector<mouse_input_sample>& left,
    std::vector<input_detection_event>& events)
{
    if (left.size() < 60 ||
        elapsed_milliseconds(
            snapshot,
            left.front().qpc,
            left.back().qpc) < 30000.0)
    {
        return false;
    }

    std::vector<double> intervals;
    for (size_t index = 1; index < left.size(); ++index)
    {
        const double delta = elapsed_milliseconds(
            snapshot,
            left[index - 1].qpc,
            left[index].qpc);
        if (delta < 0.0)
        {
            return false;
        }
        intervals.push_back(delta);
    }

    interval_statistics statistics;
    if (intervals.size() < 30 ||
        !calculate_interval_statistics(intervals, 30, statistics) ||
        statistics.mean < 50.0 ||
        !(statistics.variation < 0.06))
    {
        return false;
    }

    append_event(
        events,
        0xC3u,
        {
            static_cast<uint64_t>(
                statistics.variation * 10000.0),
            static_cast<uint64_t>(statistics.mean),
            static_cast<uint64_t>(
                statistics.deviation * 100.0),
            intervals.size(),
            1024,
        });
    return true;
}

bool analyze_continuous_window(
    const std::vector<mouse_input_sample>& left,
    const uint64_t now_tick,
    std::vector<input_detection_event>& events)
{
    const uint64_t from =
        now_tick > k_analysis_window_ms
        ? now_tick - k_analysis_window_ms
        : 0;
    if (now_tick < k_analysis_window_ms ||
        left.empty() ||
        left.back().ticks < from ||
        now_tick - left.back().ticks >= 3000)
    {
        return false;
    }

    uint32_t count = 0;
    uint32_t gaps = 0;
    for (size_t index = 0; index < left.size(); ++index)
    {
        if (left[index].ticks < from)
        {
            continue;
        }
        ++count;
        if (index > 0 &&
            left[index - 1].ticks >= from &&
            left[index].ticks - left[index - 1].ticks >= 3000)
        {
            ++gaps;
        }
    }
    if (count < 300 || gaps != 0)
    {
        return false;
    }

    append_event(events, 0xC4u, {count, 600, 1024});
    return true;
}

bool analyze_low_move_mean(
    const std::vector<mouse_input_sample>& left,
    std::vector<input_detection_event>& events)
{
    if (left.size() < 60)
    {
        return false;
    }

    uint64_t sum = 0;
    uint32_t count = 0;
    for (const mouse_input_sample& row : left)
    {
        if (!row.comparable || row.mixed_button_state)
        {
            continue;
        }
        sum += row.move_count;
        ++count;
    }
    if (count < 60)
    {
        return false;
    }
    const double mean = static_cast<double>(sum) /
        static_cast<double>(count);
    if (!(mean < 3.0))
    {
        return false;
    }

    append_event(
        events,
        0xC6u,
        {
            static_cast<uint64_t>(mean * 100.0),
            count,
            1024,
        });
    return true;
}

void analyze_mouse_and_mixed(
    const input_capture_snapshot& snapshot,
    const std::vector<mouse_input_sample>& mouse,
    const std::vector<keyboard_input_sample>& keys,
    const uint64_t now_tick,
    std::vector<input_detection_event>& events,
    bool& low_variation,
    bool& continuous_window,
    bool& low_move_mean)
{
    std::vector<mouse_input_sample> unflagged;
    std::vector<mouse_input_sample> left;
    for (const mouse_input_sample& row : mouse)
    {
        if (!row.released)
        {
            unflagged.push_back(row);
        }
        if (!row.released &&
            row.channel == 0 &&
            row.generation == snapshot.generation)
        {
            mouse_input_sample copy = row;
            if (left.empty())
            {
                copy.comparable = false;
            }
            left.push_back(copy);
        }
    }
    if (left.size() > 1024)
    {
        left.erase(left.begin(), left.end() - 1024);
        left.front().comparable = false;
    }

    uint64_t maximum_injected = 0;
    for (const mouse_input_sample& row : unflagged)
    {
        if (row.injected)
        {
            maximum_injected =
                std::max(maximum_injected, row.sequence);
        }
    }
    if (maximum_injected > g_state.last_injected_mouse)
    {
        uint32_t count = 0;
        for (const mouse_input_sample& row : unflagged)
        {
            if (row.injected)
            {
                ++count;
            }
        }
        append_event(
            events,
            0xC1u,
            {count, unflagged.size(), maximum_injected});
        g_state.last_injected_mouse = maximum_injected;
    }

    const bool new_mouse =
        !unflagged.empty() &&
        unflagged.back().sequence > g_state.last_mouse;
    const bool new_keyboard =
        !keys.empty() &&
        keys.back().sequence > g_state.last_keyboard;
    if (!unflagged.empty())
    {
        g_state.last_mouse = unflagged.back().sequence;
    }
    if (!keys.empty())
    {
        g_state.last_keyboard = keys.back().sequence;
    }

    uint64_t from = 0;
    uint64_t through = now_tick;
    if (!unflagged.empty())
    {
        bool seen[2][2] = {};
        for (const mouse_input_sample& row : unflagged)
        {
            const size_t group = row.injected ? 1u : 0u;
            if (!seen[row.channel][group])
            {
                from = std::max(from, row.ticks);
                seen[row.channel][group] = true;
            }
        }
        through = unflagged.back().ticks;
    }
    if (!keys.empty())
    {
        from = std::max(from, keys.front().ticks);
        through = std::min(through, keys.back().ticks);
    }
    if ((new_mouse || new_keyboard) &&
        through <= now_tick &&
        through >= from &&
        through - from >= 30000)
    {
        uint32_t total = 0;
        uint32_t flagged = 0;
        uint32_t flagged_keyboard = 0;
        for (const mouse_input_sample& row : unflagged)
        {
            if (row.ticks < from || row.ticks > through)
            {
                continue;
            }
            ++total;
            if (row.injected)
            {
                ++flagged;
            }
        }
        for (const keyboard_input_sample& row : keys)
        {
            if (row.ticks < from || row.ticks > through)
            {
                continue;
            }
            ++total;
            if (row.injected)
            {
                ++flagged;
                ++flagged_keyboard;
            }
        }
        if (total >= 40)
        {
            const double fraction =
                static_cast<double>(flagged) /
                static_cast<double>(total);
            if (fraction >= 0.1 && fraction <= 0.9)
            {
                append_event(
                    events,
                    0xD7u,
                    {
                        static_cast<uint64_t>(
                            fraction * 10000.0),
                        flagged,
                        total,
                        flagged_keyboard,
                        from,
                        through,
                    });
            }
        }
    }

    const bool new_left =
        !left.empty() &&
        left.back().sequence > g_state.last_left;
    if (new_left)
    {
        low_variation =
            analyze_left_variation(snapshot, left, events);
        continuous_window =
            analyze_continuous_window(left, now_tick, events);
        if (left.size() >= 60 &&
            elapsed_milliseconds(
                snapshot,
                left.front().qpc,
                left.back().qpc) >= 30000.0)
        {
            low_move_mean =
                analyze_low_move_mean(left, events);
        }
        g_state.last_left = left.back().sequence;
    }
}

void analyze_channels(
    const input_capture_snapshot& snapshot,
    const std::vector<mouse_input_sample>& mouse,
    const uint64_t now_tick,
    std::vector<input_detection_event>& events)
{
    if (mouse.empty())
    {
        return;
    }

    const uint32_t generation =
        static_cast<uint32_t>(mouse.back().generation);
    const uint64_t from =
        now_tick > k_analysis_window_ms
        ? now_tick - k_analysis_window_ms
        : 0;

    for (uint32_t channel = 0; channel < 2; ++channel)
    {
        for (uint32_t group = 0; group < 2; ++group)
        {
            std::vector<mouse_input_sample> plain;
            std::vector<mouse_input_sample> duration;
            const mouse_input_sample* previous_channel0 = nullptr;
            for (const mouse_input_sample& row : mouse)
            {
                bool follows_same_group = false;
                if (!row.released && row.channel == 0)
                {
                    follows_same_group =
                        previous_channel0 != nullptr &&
                        previous_channel0->generation == row.generation &&
                        previous_channel0->injected == row.injected;
                    previous_channel0 = &row;
                }
                if (row.channel != channel ||
                    row.injected != (group != 0) ||
                    row.generation != generation)
                {
                    continue;
                }
                if (!row.released)
                {
                    mouse_input_sample copy = row;
                    copy.mixed_button_state =
                        copy.mixed_button_state &&
                        follows_same_group;
                    plain.push_back(copy);
                }
                else if (row.duration_valid &&
                    row.ticks >= from)
                {
                    duration.push_back(row);
                }
            }

            channel_state& state = g_state.channels[channel][group];
            const uint64_t plain_sequence =
                plain.empty() ? 0 : plain.back().sequence;
            const uint64_t duration_sequence =
                duration.empty() ? 0 : duration.back().sequence;
            const bool new_plain =
                plain_sequence > state.last_plain;
            const bool new_duration =
                duration_sequence > state.last_duration;
            state.last_plain =
                std::max(state.last_plain, plain_sequence);
            state.last_duration =
                std::max(state.last_duration, duration_sequence);
            if (!new_plain && !new_duration)
            {
                continue;
            }

            const double plain_span =
                plain.size() > 1
                ? elapsed_milliseconds(
                    snapshot,
                    plain.front().qpc,
                    plain.back().qpc)
                : 0.0;
            std::vector<double> intervals;
            bool intervals_valid = true;
            double distance_sum = 0.0;
            uint32_t stationary_pairs = 0;
            uint32_t code_count = 0;
            uint64_t code_sum = 0;
            for (size_t index = 0; index < plain.size(); ++index)
            {
                const mouse_input_sample& row = plain[index];
                if (row.comparable && !row.mixed_button_state)
                {
                    code_sum += row.move_count;
                    ++code_count;
                }
                if (index == 0)
                {
                    continue;
                }
                const mouse_input_sample& previous = plain[index - 1];
                const double delta = elapsed_milliseconds(
                    snapshot,
                    previous.qpc,
                    row.qpc);
                if (delta < 0.0)
                {
                    intervals_valid = false;
                }
                intervals.push_back(delta);
                const double dx =
                    static_cast<double>(row.x) -
                    static_cast<double>(previous.x);
                const double dy =
                    static_cast<double>(row.y) -
                    static_cast<double>(previous.y);
                distance_sum += std::hypot(dx, dy);
                if (dx == 0.0 && dy == 0.0)
                {
                    ++stationary_pairs;
                }
            }

            std::vector<double> durations;
            uint32_t zero_durations = 0;
            uint32_t short_durations = 0;
            for (const mouse_input_sample& row : duration)
            {
                durations.push_back(row.duration_ms);
                if (row.duration_ms == 0.0)
                {
                    ++zero_durations;
                }
                if (row.duration_ms <= 20.0)
                {
                    ++short_durations;
                }
            }

            interval_statistics interval_stats;
            const bool interval_ok =
                intervals_valid &&
                calculate_interval_statistics(
                    intervals,
                    19,
                    interval_stats);
            interval_statistics duration_stats;
            bool duration_ok =
                calculate_interval_statistics(
                    durations,
                    20,
                    duration_stats);
            if (durations.size() >= 20 &&
                zero_durations == durations.size())
            {
                duration_ok = true;
            }

            if (state.df_count < 3 &&
                intervals_valid &&
                plain.size() >= 20 &&
                plain_span >= 30000.0 &&
                (state.last_df == 0 ||
                    now_tick - state.last_df >= 60000))
            {
                const double code_mean = code_count
                    ? static_cast<double>(code_sum) /
                        static_cast<double>(code_count)
                    : 0.0;
                const double step_mean = plain.size() > 1
                    ? distance_sum /
                        static_cast<double>(plain.size() - 1)
                    : 0.0;
                std::vector<std::string> text;
                const size_t text_start =
                    plain.size() > 8 ? plain.size() - 8 : 0;
                for (size_t index = text_start;
                    index < plain.size();
                    ++index)
                {
                    std::ostringstream row_text;
                    row_text << plain[index].ticks -
                            plain.front().ticks
                        << ":" << plain[index].x
                        << "," << plain[index].y;
                    text.push_back(row_text.str());
                }
                append_event(
                    events,
                    0xDFu,
                    {
                        1,
                        channel,
                        group,
                        plain.size(),
                        duration.size(),
                        plain_span > 0.0
                            ? static_cast<uint64_t>(plain_span)
                            : 0,
                        static_cast<uint64_t>(
                            interval_stats.mean),
                        static_cast<uint64_t>(
                            interval_stats.variation * 10000.0),
                        static_cast<uint64_t>(
                            duration_stats.mean * 100.0),
                        static_cast<uint64_t>(
                            duration_stats.variation * 10000.0),
                        zero_durations,
                        stationary_pairs,
                        plain.size() - 1,
                        static_cast<uint64_t>(step_mean * 100.0),
                        static_cast<uint64_t>(code_mean * 100.0),
                        code_count,
                        generation,
                    },
                    text);
                ++state.df_count;
                state.last_df = now_tick;
            }

            if (state.e0_count < 6 &&
                group != 0 &&
                new_plain &&
                interval_ok &&
                plain_span >= 30000.0 &&
                interval_stats.mean >= 50.0 &&
                interval_stats.variation < 0.06 &&
                (state.last_e0 == 0 ||
                    now_tick - state.last_e0 >= 60000))
            {
                append_event(
                    events,
                    0xE0u,
                    {
                        1,
                        channel,
                        static_cast<uint64_t>(
                            interval_stats.variation * 10000.0),
                        static_cast<uint64_t>(
                            interval_stats.mean),
                        static_cast<uint64_t>(
                            interval_stats.deviation * 100.0),
                        intervals.size(),
                        static_cast<uint64_t>(plain_span),
                        generation,
                    });
                ++state.e0_count;
                state.last_e0 = now_tick;
            }

            const double duration_span =
                durations.size() > 1
                ? elapsed_milliseconds(
                    snapshot,
                    duration.front().qpc,
                    duration.back().qpc)
                : 0.0;
            if (state.e1_count < 3 &&
                new_duration &&
                duration_ok &&
                duration_span >= 30000.0 &&
                duration_stats.variation < 0.06 &&
                (state.last_e1 == 0 ||
                    now_tick - state.last_e1 >= 60000))
            {
                append_event(
                    events,
                    0xE1u,
                    {
                        1,
                        channel,
                        group,
                        static_cast<uint64_t>(
                            duration_stats.variation * 10000.0),
                        static_cast<uint64_t>(
                            duration_stats.mean * 100.0),
                        static_cast<uint64_t>(
                            duration_stats.deviation * 100.0),
                        durations.size(),
                        static_cast<uint64_t>(duration_span),
                        zero_durations,
                        generation,
                    });
                ++state.e1_count;
                state.last_e1 = now_tick;
            }

            if (state.e2_count < 3 &&
                group != 0 &&
                new_duration &&
                durations.size() >= 20 &&
                duration_span >= 30000.0 &&
                static_cast<uint64_t>(short_durations) * 100 >=
                    static_cast<uint64_t>(durations.size()) * 80 &&
                (state.last_e2 == 0 ||
                    now_tick - state.last_e2 >= 60000))
            {
                append_event(
                    events,
                    0xE2u,
                    {
                        1,
                        channel,
                        static_cast<uint64_t>(short_durations) *
                            10000 /
                            durations.size(),
                        short_durations,
                        durations.size(),
                        zero_durations,
                        20,
                        80,
                        static_cast<uint64_t>(duration_span),
                        static_cast<uint64_t>(
                            duration_stats.mean * 100.0),
                        generation,
                    });
                ++state.e2_count;
                state.last_e2 = now_tick;
            }
        }
    }
}
}

std::vector<input_detection_event> analyze_input_capture(
    const input_capture_snapshot& snapshot,
    const uint64_t now_tick)
{
    std::lock_guard<std::mutex> lock(g_state_mutex);
    if (!snapshot.capture_ready ||
        snapshot.started_tick == 0 ||
        now_tick < snapshot.started_tick ||
        now_tick - snapshot.started_tick < k_capture_warmup_ms)
    {
        return {};
    }

    if (g_state.generation != snapshot.generation)
    {
        g_state = {};
        g_state.generation = snapshot.generation;
    }

    const uint64_t from =
        now_tick > k_analysis_window_ms
        ? now_tick - k_analysis_window_ms
        : 0;

    std::vector<keyboard_input_sample> keys;
    for (const keyboard_input_sample& row : snapshot.keyboard)
    {
        if (row.generation == snapshot.generation &&
            row.ticks >= from &&
            row.ticks <= now_tick)
        {
            keys.push_back(row);
        }
    }

    std::vector<mouse_input_sample> mouse;
    for (const mouse_input_sample& row : snapshot.mouse)
    {
        if (row.generation == snapshot.generation &&
            row.ticks >= from &&
            row.ticks <= now_tick)
        {
            mouse.push_back(row);
        }
    }

    std::vector<input_detection_event> events;
    analyze_keyboard(snapshot, keys, events);
    bool low_variation = false;
    bool continuous_window = false;
    bool low_move_mean = false;
    analyze_mouse_and_mixed(
        snapshot,
        mouse,
        keys,
        now_tick,
        events,
        low_variation,
        continuous_window,
        low_move_mean);
    analyze_channels(snapshot, mouse, now_tick, events);
    if (low_variation && continuous_window && low_move_mean)
    {
        append_event(events, 0xE3u);
    }
    return events;
}

void reset_input_detection_state()
{
    std::lock_guard<std::mutex> lock(g_state_mutex);
    g_state = {};
}
}
