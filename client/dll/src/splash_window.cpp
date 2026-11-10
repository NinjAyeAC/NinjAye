#include "splash_window.h"

#include <xorstr.hpp>
#include <windows.h>

#include <string>

namespace ninjaye
{
namespace
{
constexpr UINT_PTR kCloseTimer = 1;
constexpr UINT kSplashLifetimeMs = 1500;

const wchar_t* window_class_name()
{
    static const std::wstring value =
        xorstr_(L"NinjAyeSplashWindow");
    return value.c_str();
}

LRESULT CALLBACK splash_window_proc(
    HWND window,
    UINT message,
    WPARAM w_param,
    LPARAM l_param)
{
    switch (message)
    {
    case WM_CREATE:
        SetTimer(window, kCloseTimer, kSplashLifetimeMs, nullptr);
        return 0;
    case WM_TIMER:
        if (w_param == kCloseTimer)
        {
            KillTimer(window, kCloseTimer);
            DestroyWindow(window);
        }
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
    {
        PAINTSTRUCT paint = {};
        HDC device = BeginPaint(window, &paint);
        RECT client = {};
        GetClientRect(window, &client);

        HBRUSH background = CreateSolidBrush(RGB(10, 15, 24));
        FillRect(device, &client, background);
        DeleteObject(background);

        HBRUSH accent = CreateSolidBrush(RGB(38, 214, 170));
        RECT accent_rect = {
            48,
            client.bottom - 34,
            client.right - 48,
            client.bottom - 28,
        };
        FillRect(device, &accent_rect, accent);
        DeleteObject(accent);

        SetBkMode(device, TRANSPARENT);
        SetTextColor(device, RGB(232, 245, 244));
        HFONT title_font = CreateFontW(
            46,
            0,
            0,
            0,
            FW_SEMIBOLD,
            FALSE,
            FALSE,
            FALSE,
            DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY,
            DEFAULT_PITCH,
            L"Segoe UI");
        HGDIOBJ old_font = SelectObject(device, title_font);
        RECT title_rect = {48, 54, client.right - 48, 120};
        DrawTextW(
            device,
            xorstr_(L"NinjAye"),
            -1,
            &title_rect,
            DT_LEFT | DT_SINGLELINE);

        SelectObject(device, old_font);
        DeleteObject(title_font);

        SetTextColor(device, RGB(125, 151, 160));
        HFONT body_font = CreateFontW(
            18,
            0,
            0,
            0,
            FW_NORMAL,
            FALSE,
            FALSE,
            FALSE,
            DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY,
            DEFAULT_PITCH,
            L"Segoe UI");
        old_font = SelectObject(device, body_font);
        RECT body_rect = {50, 128, client.right - 48, 160};
        DrawTextW(
            device,
            xorstr_(L"Runtime protection initializing"),
            -1,
            &body_rect,
            DT_LEFT | DT_SINGLELINE);
        SelectObject(device, old_font);
        DeleteObject(body_font);

        EndPaint(window, &paint);
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(window, message, w_param, l_param);
    }
}
}

void run_splash_window()
{
    const HINSTANCE instance = GetModuleHandleW(nullptr);

    WNDCLASSEXW window_class = {};
    window_class.cbSize = sizeof(window_class);
    window_class.lpfnWndProc = splash_window_proc;
    window_class.hInstance = instance;
    window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    window_class.hbrBackground = nullptr;
    window_class.lpszClassName = window_class_name();
    RegisterClassExW(&window_class);

    const int width = 520;
    const int height = 220;
    const int x = (GetSystemMetrics(SM_CXSCREEN) - width) / 2;
    const int y = (GetSystemMetrics(SM_CYSCREEN) - height) / 2;

    HWND window = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TOOLWINDOW,
        window_class_name(),
        xorstr_(L"NinjAye"),
        WS_POPUP,
        x,
        y,
        width,
        height,
        nullptr,
        nullptr,
        instance,
        nullptr);
    if (window != nullptr)
    {
        SetLayeredWindowAttributes(window, 0, 238, LWA_ALPHA);
        ShowWindow(window, SW_SHOWNOACTIVATE);
        UpdateWindow(window);

        MSG message = {};
        while (GetMessageW(&message, nullptr, 0, 0) > 0)
        {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }

    UnregisterClassW(window_class_name(), instance);
}
}
