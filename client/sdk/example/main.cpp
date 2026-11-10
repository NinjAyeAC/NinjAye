#include "client.h"
#include "server.h"

#include <xorstr.hpp>
#include <windows.h>

#include <array>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <string>
#include <thread>

namespace
{
ninjaye::client g_client;
volatile LONG g_stop = 0;

BOOL WINAPI console_handler(const DWORD control_type)
{
    if (control_type == CTRL_C_EVENT ||
        control_type == CTRL_BREAK_EVENT ||
        control_type == CTRL_CLOSE_EVENT)
    {
        InterlockedExchange(&g_stop, 1);
        return TRUE;
    }
    return FALSE;
}

std::wstring utf8_to_wide_simple(const std::string& value)
{
    if (value.empty())
    {
        return {};
    }

    const int required = MultiByteToWideChar(
        CP_UTF8,
        0,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0);
    std::wstring output(static_cast<size_t>(required), L'\0');
    MultiByteToWideChar(
        CP_UTF8,
        0,
        value.data(),
        static_cast<int>(value.size()),
        output.data(),
        required);
    return output;
}

void print_error_code(const ninjaye::sdk_error error)
{
    std::cerr
        << xorstr_("0x")
        << std::hex << std::uppercase
        << std::setw(8) << std::setfill('0')
        << static_cast<uint32_t>(error)
        << std::dec << std::nouppercase << xorstr_("\n");
}

void print_identity(
    const char* label,
    const std::array<uint8_t, 32>& identity)
{
    std::cout << label;
    for (const uint8_t byte : identity)
    {
        std::cout << std::hex << std::uppercase
            << std::setw(2) << std::setfill('0')
            << static_cast<unsigned int>(byte);
    }
    std::cout << std::dec << xorstr_("\n");
}

}

int wmain(const int argc, wchar_t** argv)
{
    if (argc < 2)
    {
        std::wcerr
            << xorstr_(
                L"usage: ninjaye_sdk_example.exe "
                L"<server-url> [dll-path] "
                L"[--test-rx-region] [--run-once]\n");
        return 2;
    }

    bool test_rx_region = false;
    bool run_once = false;
    std::wstring requested_dll_path;
    for (int index = 2; index < argc; ++index)
    {
        if (std::wstring(argv[index]) ==
            xorstr_(L"--test-rx-region"))
        {
            test_rx_region = true;
        }
        else if (std::wstring(argv[index]) ==
            xorstr_(L"--run-once"))
        {
            run_once = true;
        }
        else
        {
            requested_dll_path = argv[index];
        }
    }

    wchar_t executable[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, executable, static_cast<DWORD>(std::size(executable)));
    std::wstring executable_path(executable);
    const size_t separator = executable_path.find_last_of(xorstr_(L"\\/"));
    const std::wstring base_dir = separator == std::wstring::npos
        ? xorstr_(L".")
        : executable_path.substr(0, separator);
    const std::wstring dll_path =
        requested_dll_path.empty()
        ? base_dir + xorstr_(L"\\NinjAye.dll")
        : requested_dll_path;

    if (!g_client.load(dll_path))
    {
        print_error_code(g_client.error_code());
        return 1;
    }

    void* test_region = nullptr;
    if (test_rx_region)
    {
        test_region = VirtualAlloc(
            nullptr,
            4096,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
        if (test_region == nullptr)
        {
            std::cerr
                << xorstr_("test RX allocation failed\n");
            return 1;
        }
    }

    const auto release_test_region = [&]()
    {
        if (test_region != nullptr)
        {
            VirtualFree(test_region, 0, MEM_RELEASE);
            test_region = nullptr;
        }
    };

    if (!g_client.start(argv[1]))
    {
        print_error_code(g_client.error_code());
        release_test_region();
        return 1;
    }

    std::array<uint8_t, 32> machine_identity = {};
    std::array<uint8_t, 32> cpu_disk_identity = {};
    std::array<uint8_t, 32> tpm_identity = {};
    std::array<uint8_t, 32> profile_list_identity = {};
    std::array<uint8_t, 32> file_id_identity = {};
    if (g_client.copy_machine_identity(machine_identity))
    {
        print_identity(
            xorstr_("ClientId:   "),
            machine_identity);
    }
    if (g_client.copy_cpu_disk_identity(cpu_disk_identity))
    {
        print_identity(
            xorstr_("ClientIdV2: "),
            cpu_disk_identity);
    }
    if (g_client.copy_tpm_identity(tpm_identity))
    {
        print_identity(
            xorstr_("ClientIdV3: "),
            tpm_identity);
    }
    if (g_client.copy_profile_list_identity(profile_list_identity))
    {
        print_identity(
            xorstr_("ClientIdV4: "),
            profile_list_identity);
    }
    if (g_client.copy_file_id_identity(file_id_identity))
    {
        print_identity(
            xorstr_("ClientIdV5: "),
            file_id_identity);
    }

    const std::array<uint8_t, 8> opaque_echo = {
        0x4E, 0x69, 0x6E, 0x6A,
        0x41, 0x79, 0x65, 0x00,
    };
    const uint32_t profile_seed =
        challenge_server::file_crc32c(dll_path);
    if (profile_seed == 0)
    {
        std::cerr << xorstr_("DLL profile seed calculation failed\n");
        g_client.stop();
        release_test_region();
        return 1;
    }
    challenge_server game_server(profile_seed, 0xFFFFFFFFu);
    challenge_client game_client(g_client);
    const gc_packet_aa challenge_packet =
        game_server.create_challenge(
            0x12345678u,
            opaque_echo);
    gc_packet_aa challenge_reply;
    if (!game_client.process_challenge(
            challenge_packet,
            challenge_reply))
    {
        std::cerr << xorstr_("AA packet handling failed\n");
        g_client.stop();
        release_test_region();
        return 1;
    }
    const uint32_t expected_reply =
        game_server.expected_response(challenge_packet.message);
    if (challenge_reply.message != expected_reply)
    {
        std::cerr
            << xorstr_("AA challenge_reply.message mismatch\n");
        g_client.stop();
        release_test_region();
        return 1;
    }
    if (!game_server.verify_response(
            challenge_packet,
            challenge_reply))
    {
        std::cerr << xorstr_("AA packet verification failed\n");
        g_client.stop();
        release_test_region();
        return 1;
    }
    std::cout
        << xorstr_("AA packet 0x12345678 -> 0x")
        << std::hex << std::uppercase << challenge_reply.message
        << std::dec << xorstr_("\n");
    std::cout
        << xorstr_("AA challenge_reply.message == expected: OK\n");
    std::cout << xorstr_("AA packet server verification: OK\n");

    std::cout
        << (run_once
            ? xorstr_("NinjAye started. Run-once test active.\n")
            : xorstr_("NinjAye started. Press Ctrl+C to stop.\n"));

    if (run_once)
    {
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    else
    {
        SetConsoleCtrlHandler(console_handler, TRUE);
        while (InterlockedCompareExchange(&g_stop, 0, 0) == 0)
        {
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }

    g_client.stop();
    release_test_region();
    return 0;
}
