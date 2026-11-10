#ifndef NINJAYE_SDK_H
#define NINJAYE_SDK_H

#include "../../dll/include/ninjaye_bridge.h"

#include <windows.h>

#include <array>
#include <future>
#include <mutex>
#include <string>

namespace ninjaye
{
enum class sdk_error : uint32_t
{
    none = 0x00000000,
    dll_path_invalid = 0x00010001,
    dll_path_missing = 0x00010002,
    low_config_allocation_failed = 0x00020001,
    semaphore_name_too_long = 0x00020002,
    server_address_invalid = 0x00020003,
    startup_config_unencodable = 0x00020004,
    create_semaphore_failed = 0x00030001,
    load_library_failed = 0x00030002,
    another_instance_active = 0x00040001,
    message_function_missing = 0x00050001,
    identity_function_missing = 0x00050002,
};
static_assert(sizeof(sdk_error) == sizeof(uint32_t));
static_assert(static_cast<uint32_t>(sdk_error::none) == 0);

enum class notification_command : uint32_t
{
    challenge = 0,
    client_id = 1,
    client_id_v2 = 2,
    client_id_v3 = 3,
    client_id_v4 = 4,
    client_id_v5 = 5,
};
static_assert(sizeof(notification_command) == sizeof(uint32_t));
static_assert(
    static_cast<uint32_t>(notification_command::challenge) == 0);
static_assert(
    static_cast<uint32_t>(notification_command::client_id_v5) == 5);

class client
{
public:
    client();
    ~client();

    client(const client&) = delete;
    client& operator=(const client&) = delete;

    bool load(const std::wstring& dll_path);

    bool start(const std::wstring& server_address);

    void stop();

    bool resolve_challenge(
        uint32_t message,
        uint32_t& response) const;

    bool copy_identity(
        notification_command command,
        std::array<uint8_t, 32>& identity) const;

    bool copy_machine_identity(
        std::array<uint8_t, 32>& identity) const;

    bool copy_cpu_disk_identity(
        std::array<uint8_t, 32>& identity) const;

    bool copy_tpm_identity(
        std::array<uint8_t, 32>& identity) const;

    bool copy_profile_list_identity(
        std::array<uint8_t, 32>& identity) const;

    bool copy_file_id_identity(
        std::array<uint8_t, 32>& identity) const;

    sdk_error error_code() const noexcept;

private:
    static void NINJAYE_BRIDGE_CALL notification_callback(
        uint32_t command,
        const void* buffer_or_pointer,
        uint32_t size);

    bool create_low_config(const std::wstring& server_address);

    void release_startup_storage();

    std::wstring dll_path_;
    sdk_error error_ = sdk_error::none;

    std::promise<void> ready_promise_;
    std::future<void> ready_future_;
    std::once_flag ready_once_;
    mutable std::mutex published_mutex_;
    ninjaye_message_function message_function_ = nullptr;
    std::array<ninjaye_identity_function, 5> identity_functions_ = {};

    void* startup_storage_ = nullptr;
    HANDLE semaphore_ = nullptr;
    wchar_t* name_buffer_ = nullptr;

    static client* active_instance_;
    static std::mutex active_instance_mutex_;
};
}

#endif
