#include "input_capture.h"

#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <future>
#include <mutex>
#include <thread>
#include <utility>

namespace ninjaye
{
namespace
{
struct pending_mouse_press
{
    bool active = false;
    uint64_t ticks = 0;
    int64_t qpc = 0;
    uint64_t generation = 0;
    bool injected = false;
};

std::mutex g_input_mutex;
std::vector<keyboard_input_sample> g_keyboard_samples;
std::vector<mouse_input_sample> g_mouse_samples;
std::array<bool, 256> g_key_state = {};
std::array<pending_mouse_press, 2> g_pending_mouse = {};
std::atomic<bool> g_capture_ready = false;
std::atomic<bool> g_stop_requested = false;
std::atomic<uint64_t> g_keyboard_sequence = 0;
std::atomic<uint64_t> g_mouse_sequence = 0;
std::atomic<uint32_t> g_move_count = 0;
std::atomic<uint64_t> g_generation = 1;
std::atomic<uint64_t> g_started_tick = 0;
std::thread g_hook_thread;
DWORD g_hook_thread_id = 0;
HHOOK g_keyboard_hook = nullptr;
HHOOK g_mouse_hook = nullptr;
std::int64_t g_qpc_frequency = 0;
bool g_foreground_match = false;

constexpr size_t k_max_keyboard_samples = 256;
constexpr size_t k_max_mouse_samples = 8192;
constexpr uint32_t k_max_move_count = 0xFFFFu;

bool foreground_matches_current_process()
{
    const HWND foreground = GetForegroundWindow();
    if (foreground == nullptr)
    {
        return false;
    }
    DWORD process_id = 0;
    GetWindowThreadProcessId(foreground, &process_id);
    return process_id == GetCurrentProcessId();
}

void update_generation(const bool foreground_match)
{
    if (foreground_match && !g_foreground_match)
    {
        g_generation.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard<std::mutex> lock(g_input_mutex);
            g_pending_mouse = {};
        }
    }
    g_foreground_match = foreground_match;
}

uint32_t saturated_move_count()
{
    uint32_t current = g_move_count.load(std::memory_order_relaxed);
    while (current < k_max_move_count &&
        !g_move_count.compare_exchange_weak(
            current,
            current + 1,
            std::memory_order_relaxed))
    {
    }
    return std::min(current, k_max_move_count);
}

void append_keyboard_sample(
    const uint32_t virtual_key,
    const bool injected)
{
    if (virtual_key > 0xFFu)
    {
        return;
    }

    keyboard_input_sample sample;
    sample.ticks = GetTickCount64();
    QueryPerformanceCounter(
        reinterpret_cast<LARGE_INTEGER*>(&sample.qpc));
    sample.sequence =
        g_keyboard_sequence.fetch_add(1, std::memory_order_relaxed) + 1;
    sample.generation = g_generation.load(std::memory_order_relaxed);
    sample.code = virtual_key;
    sample.injected = injected;

    std::lock_guard<std::mutex> lock(g_input_mutex);
    if (g_keyboard_samples.size() == k_max_keyboard_samples)
    {
        g_keyboard_samples.erase(g_keyboard_samples.begin());
    }
    g_keyboard_samples.push_back(sample);
}

double qpc_delta_to_milliseconds(const int64_t delta)
{
    if (delta < 0 || g_qpc_frequency <= 0)
    {
        return -1.0;
    }
    return static_cast<double>(delta) * 1000.0 /
        static_cast<double>(g_qpc_frequency);
}

uint32_t mouse_channel(const WPARAM message)
{
    switch (message)
    {
    case WM_LBUTTONDOWN:
    case WM_LBUTTONUP:
        return 0;
    case WM_RBUTTONDOWN:
    case WM_RBUTTONUP:
        return 1;
    default:
        return 0xFFFFFFFFu;
    }
}

bool mouse_release(const WPARAM message)
{
    return message == WM_LBUTTONUP || message == WM_RBUTTONUP;
}

void append_mouse_sample(
    const MSLLHOOKSTRUCT& input,
    const uint32_t channel,
    const bool release)
{
    const bool injected = (input.flags & LLMHF_INJECTED) != 0;
    mouse_input_sample sample;
    sample.ticks = GetTickCount64();
    sample.qpc = static_cast<int64_t>(input.time);
    QueryPerformanceCounter(
        reinterpret_cast<LARGE_INTEGER*>(&sample.qpc));
    sample.sequence =
        g_mouse_sequence.fetch_add(1, std::memory_order_relaxed) + 1;
    sample.generation = g_generation.load(std::memory_order_relaxed);
    sample.x = input.pt.x;
    sample.y = input.pt.y;
    sample.move_count = g_move_count.load(std::memory_order_relaxed);
    sample.channel = channel;
    sample.injected = injected;
    sample.released = release;

    {
        std::lock_guard<std::mutex> lock(g_input_mutex);
        auto& pending = g_pending_mouse[channel];
        if (!release)
        {
            sample.comparable = true;
            sample.mixed_button_state = false;
            if (channel == 0)
            {
                const auto previous = std::find_if(
                    g_mouse_samples.rbegin(),
                    g_mouse_samples.rend(),
                    [](const mouse_input_sample& value)
                    {
                        return value.channel == 0 && !value.released;
                    });
                sample.mixed_button_state =
                    g_pending_mouse[1].active ||
                    (previous != g_mouse_samples.rend() &&
                        previous->ticks + 3000 < sample.ticks);
            }
            pending.active = true;
            pending.ticks = sample.ticks;
            pending.qpc = sample.qpc;
            pending.generation = sample.generation;
            pending.injected = injected;
        }
        else
        {
            if (!pending.active ||
                pending.generation != sample.generation ||
                pending.injected != injected)
            {
                return;
            }
            const int64_t qpc_delta = sample.qpc - pending.qpc;
            const uint64_t tick_delta = sample.ticks >= pending.ticks
                ? sample.ticks - pending.ticks
                : 0;
            sample.duration_ms =
                qpc_delta_to_milliseconds(qpc_delta);
            sample.duration_valid =
                tick_delta <= 600000 &&
                std::isfinite(sample.duration_ms) &&
                sample.duration_ms >= 0.0 &&
                sample.duration_ms <= 600000.0;
            if (!sample.duration_valid)
            {
                sample.duration_ms = 0.0;
            }
            pending = {};
        }

        if (g_mouse_samples.size() == k_max_mouse_samples)
        {
            g_mouse_samples.erase(g_mouse_samples.begin());
        }
        g_mouse_samples.push_back(sample);
    }
}

LRESULT CALLBACK keyboard_hook_proc(
    const int code,
    const WPARAM message,
    const LPARAM event)
{
    if (code >= 0 &&
        (message == WM_KEYDOWN || message == WM_SYSKEYDOWN ||
         message == WM_KEYUP || message == WM_SYSKEYUP))
    {
        const auto* input =
            reinterpret_cast<const KBDLLHOOKSTRUCT*>(event);
        const bool foreground =
            foreground_matches_current_process();
        update_generation(foreground);
        if (foreground && input->vkCode <= 0xFFu)
        {
            const size_t key = static_cast<size_t>(input->vkCode);
            if (message == WM_KEYDOWN || message == WM_SYSKEYDOWN)
            {
                if (!g_key_state[key])
                {
                    g_key_state[key] = true;
                    append_keyboard_sample(
                        input->vkCode,
                        (input->flags & LLKHF_INJECTED) != 0);
                }
            }
            else
            {
                g_key_state[key] = false;
            }
        }
    }
    return CallNextHookEx(g_keyboard_hook, code, message, event);
}

LRESULT CALLBACK mouse_hook_proc(
    const int code,
    const WPARAM message,
    const LPARAM event)
{
    if (code >= 0)
    {
        const auto* input =
            reinterpret_cast<const MSLLHOOKSTRUCT*>(event);
        const bool foreground =
            foreground_matches_current_process();
        update_generation(foreground);
        if (foreground)
        {
            if (message == WM_MOUSEMOVE)
            {
                saturated_move_count();
            }
            else
            {
                const uint32_t channel = mouse_channel(message);
                if (channel < 2)
                {
                    append_mouse_sample(
                        *input,
                        channel,
                        mouse_release(message));
                }
            }
        }
    }
    return CallNextHookEx(g_mouse_hook, code, message, event);
}

void hook_thread_main(std::promise<bool> ready)
{
    g_hook_thread_id = GetCurrentThreadId();
    MSG message = {};
    PeekMessageW(&message, nullptr, WM_USER, WM_USER, PM_NOREMOVE);
    QueryPerformanceFrequency(
        reinterpret_cast<LARGE_INTEGER*>(&g_qpc_frequency));
    g_started_tick = GetTickCount64();

    HMODULE module = nullptr;
    GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&keyboard_hook_proc),
        &module);

    g_keyboard_hook = SetWindowsHookExW(
        WH_KEYBOARD_LL,
        keyboard_hook_proc,
        module,
        0);
    g_mouse_hook = SetWindowsHookExW(
        WH_MOUSE_LL,
        mouse_hook_proc,
        module,
        0);
    const bool installed =
        g_keyboard_hook != nullptr &&
        g_mouse_hook != nullptr;
    g_capture_ready = installed;
    ready.set_value(installed);
    if (!installed)
    {
        if (g_keyboard_hook != nullptr)
        {
            UnhookWindowsHookEx(g_keyboard_hook);
            g_keyboard_hook = nullptr;
        }
        if (g_mouse_hook != nullptr)
        {
            UnhookWindowsHookEx(g_mouse_hook);
            g_mouse_hook = nullptr;
        }
        return;
    }

    message = {};
    while (GetMessageW(&message, nullptr, 0, 0) > 0)
    {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    if (g_mouse_hook != nullptr)
    {
        UnhookWindowsHookEx(g_mouse_hook);
        g_mouse_hook = nullptr;
    }
    if (g_keyboard_hook != nullptr)
    {
        UnhookWindowsHookEx(g_keyboard_hook);
        g_keyboard_hook = nullptr;
    }
    g_capture_ready = false;
}
}

bool start_input_capture()
{
    if (g_hook_thread.joinable())
    {
        return g_capture_ready.load();
    }

    {
        std::lock_guard<std::mutex> lock(g_input_mutex);
        g_keyboard_samples.clear();
        g_mouse_samples.clear();
        g_pending_mouse = {};
    }
    g_key_state.fill(false);
    g_stop_requested = false;
    g_keyboard_sequence = 0;
    g_mouse_sequence = 0;
    g_move_count = 0;
    g_generation = 1;
    g_foreground_match = false;

    std::promise<bool> ready;
    std::future<bool> ready_future = ready.get_future();
    g_hook_thread = std::thread(
        hook_thread_main,
        std::move(ready));
    if (ready_future.wait_for(std::chrono::seconds(3)) !=
        std::future_status::ready)
    {
        stop_input_capture();
        return false;
    }
    return ready_future.get();
}

void stop_input_capture()
{
    if (!g_hook_thread.joinable())
    {
        g_capture_ready = false;
        return;
    }

    g_stop_requested = true;
    if (g_hook_thread_id != 0)
    {
        PostThreadMessageW(g_hook_thread_id, WM_QUIT, 0, 0);
    }
    g_hook_thread.join();
    g_hook_thread_id = 0;
    g_capture_ready = false;
}

input_capture_snapshot snapshot_input_capture()
{
    input_capture_snapshot snapshot;
    snapshot.capture_ready = g_capture_ready.load();
    snapshot.generation = g_generation.load();
    snapshot.started_tick = g_started_tick.load();
    snapshot.qpc_frequency = g_qpc_frequency;
    snapshot.maximum_keyboard_sequence =
        g_keyboard_sequence.load();
    snapshot.maximum_mouse_sequence =
        g_mouse_sequence.load();
    {
        std::lock_guard<std::mutex> lock(g_input_mutex);
        snapshot.keyboard = g_keyboard_samples;
        snapshot.mouse = g_mouse_samples;
    }
    return snapshot;
}
}
