#include "../include/ninjaye_sdk.h"
#include <xorstr.hpp>

namespace ninjaye
{
client* client::active_instance_ = nullptr;
std::mutex client::active_instance_mutex_;

namespace
{
std::wstring decimal_process_id()
{
    return std::to_wstring(GetCurrentProcessId());
}

void* allocate_low_config()
{
    constexpr std::array<uintptr_t, 8> candidates = {
        0x10000000,
        0x20000000,
        0x30000000,
        0x40000000,
        0x50000000,
        0x60000000,
        0x70000000,
        0x00010000,
    };

    for (const uintptr_t candidate : candidates)
    {
        void* memory = VirtualAlloc(
            reinterpret_cast<void*>(candidate),
            0x1000,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE);
        if (memory != nullptr)
        {
            return memory;
        }
    }
    return nullptr;
}

}

client::client()
{
    dll_path_ = xorstr_(L"NinjAye.dll");
    ready_future_ = ready_promise_.get_future();
}

client::~client()
{
    stop();
    release_startup_storage();
}

bool client::load(const std::wstring& dll_path)
{
    error_ = sdk_error::none;
    if (dll_path.empty() || GetFileAttributesW(dll_path.c_str()) ==
        INVALID_FILE_ATTRIBUTES)
    {
        error_ = sdk_error::dll_path_invalid;
        return false;
    }
    dll_path_ = dll_path;
    return true;
}

void client::release_startup_storage()
{
    if (semaphore_ != nullptr)
    {
        CloseHandle(semaphore_);
        semaphore_ = nullptr;
    }
    if (startup_storage_ != nullptr)
    {
        VirtualFree(startup_storage_, 0, MEM_RELEASE);
        startup_storage_ = nullptr;
    }
    name_buffer_ = nullptr;
}

void NINJAYE_BRIDGE_CALL client::notification_callback(
    const uint32_t command,
    const void* buffer_or_pointer,
    const uint32_t size)
{
    (void)size;

    client* instance = nullptr;
    {
        std::lock_guard<std::mutex> lock(active_instance_mutex_);
        instance = active_instance_;
    }
    if (instance == nullptr)
    {
        return;
    }

    const notification_command command_id =
        static_cast<notification_command>(command);
    bool startup_complete = false;
    {
        std::lock_guard<std::mutex> lock(instance->published_mutex_);
        switch (command_id)
        {
        case notification_command::challenge:
            instance->message_function_ =
                reinterpret_cast<ninjaye_message_function>(
                    const_cast<void*>(buffer_or_pointer));
            break;
        case notification_command::client_id:
        case notification_command::client_id_v2:
        case notification_command::client_id_v3:
        case notification_command::client_id_v4:
        case notification_command::client_id_v5:
        {
            const size_t index =
                static_cast<uint32_t>(command_id) - 1;
            instance->identity_functions_[index] =
                reinterpret_cast<ninjaye_identity_function>(
                    const_cast<void*>(buffer_or_pointer));
            break;
        }
        default:
            return;
        }

        startup_complete =
            instance->message_function_ != nullptr;
        for (ninjaye_identity_function function :
            instance->identity_functions_)
        {
            startup_complete =
                startup_complete && function != nullptr;
        }
    }

    if (startup_complete)
    {
        std::call_once(
            instance->ready_once_,
            [instance]()
            {
                instance->ready_promise_.set_value();
            });
    }
}

bool client::create_low_config(const std::wstring& server_address)
{
    startup_storage_ = allocate_low_config();
    if (startup_storage_ == nullptr)
    {
        error_ = sdk_error::low_config_allocation_failed;
        return false;
    }

    auto* config = static_cast<ninjaye_client_config24*>(startup_storage_);
    auto* name_storage = reinterpret_cast<wchar_t*>(
        static_cast<unsigned char*>(startup_storage_) + 0x40);
    auto* server_storage = reinterpret_cast<wchar_t*>(
        static_cast<unsigned char*>(startup_storage_) + 0x800);
    name_buffer_ = name_storage;

    const std::wstring name =
        xorstr_(L"Local\\NinjAye") + decimal_process_id();
    if (name.size() + 1 > 0x1000 / sizeof(wchar_t) - 0x20)
    {
        error_ = sdk_error::semaphore_name_too_long;
        return false;
    }
    wcscpy_s(name_storage, 0x1000 / sizeof(wchar_t), name.c_str());

    config->marker = reinterpret_cast<uint32_t*>(name_storage);
    config->callback = &client::notification_callback;
    config->server_address = server_storage;

    constexpr size_t server_capacity =
        (0x1000 - 0x800) / sizeof(wchar_t);
    if (server_address.empty() ||
        (server_address.rfind(L"https://", 0) != 0 &&
         server_address.rfind(L"http://", 0) != 0) ||
        server_address.size() + 1 > server_capacity)
    {
        error_ = sdk_error::server_address_invalid;
        return false;
    }
    wcscpy_s(
        server_storage,
        server_capacity,
        server_address.c_str());

    const uintptr_t address = reinterpret_cast<uintptr_t>(config);
    if (address > 0x7FFFFFFF)
    {
        error_ = sdk_error::startup_config_unencodable;
        return false;
    }

    semaphore_ = CreateSemaphoreExW(
        nullptr,
        static_cast<LONG>(address >> 31),
        static_cast<LONG>(address & 0x7FFFFFFF),
        name.c_str(),
        0,
        SEMAPHORE_ALL_ACCESS);
    *reinterpret_cast<uint32_t*>(name_storage) = NINJAYE_PROFILE_MARKER;
    const DWORD semaphore_error = GetLastError();
    if (semaphore_error == ERROR_ALREADY_EXISTS ||
        semaphore_ == nullptr)
    {
        error_ = sdk_error::create_semaphore_failed;
        return false;
    }

    const HMODULE loaded_module = LoadLibraryW(dll_path_.c_str());
    if (loaded_module == nullptr)
    {
        error_ = sdk_error::load_library_failed;
        return false;
    }
    (void)loaded_module;
    return true;
}

bool client::start(const std::wstring& server_address)
{
    error_ = sdk_error::none;
    if (dll_path_.empty())
    {
        error_ = sdk_error::dll_path_missing;
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(active_instance_mutex_);
        if (active_instance_ != nullptr && active_instance_ != this)
        {
            error_ = sdk_error::another_instance_active;
            return false;
        }
        active_instance_ = this;
    }

    if (!create_low_config(server_address))
    {
        std::lock_guard<std::mutex> lock(active_instance_mutex_);
        if (active_instance_ == this)
        {
            active_instance_ = nullptr;
        }
        return false;
    }

    ready_future_.wait();

    if (semaphore_ != nullptr)
    {
        CloseHandle(semaphore_);
        semaphore_ = nullptr;
    }
    if (startup_storage_ != nullptr)
    {
        VirtualFree(startup_storage_, 0, MEM_RELEASE);
        startup_storage_ = nullptr;
        name_buffer_ = nullptr;
    }

    {
        std::lock_guard<std::mutex> lock(published_mutex_);
        if (message_function_ == nullptr)
        {
            error_ = sdk_error::message_function_missing;
            return false;
        }
        for (ninjaye_identity_function function :
            identity_functions_)
        {
            if (function == nullptr)
            {
                error_ = sdk_error::identity_function_missing;
                return false;
            }
        }
    }
    return true;
}

void client::stop()
{
    {
        std::lock_guard<std::mutex> lock(published_mutex_);
        message_function_ = nullptr;
        identity_functions_.fill(nullptr);
    }
    {
        std::lock_guard<std::mutex> lock(active_instance_mutex_);
        if (active_instance_ == this)
        {
            active_instance_ = nullptr;
        }
    }
}

bool client::resolve_challenge(
    const uint32_t message,
    uint32_t& response) const
{
    std::lock_guard<std::mutex> lock(published_mutex_);
    if (message_function_ == nullptr)
    {
        return false;
    }
    response = message_function_(message);
    return true;
}

bool client::copy_identity(
    const notification_command command,
    std::array<uint8_t, 32>& identity) const
{
    const uint32_t command_value =
        static_cast<uint32_t>(command);
    if (command_value <
            static_cast<uint32_t>(
                notification_command::client_id) ||
        command_value >
            static_cast<uint32_t>(
                notification_command::client_id_v5))
    {
        return false;
    }

    std::lock_guard<std::mutex> lock(published_mutex_);
    const ninjaye_identity_function function =
        identity_functions_[command_value - 1];
    if (function == nullptr)
    {
        return false;
    }
    function(identity.data());
    return true;
}

bool client::copy_machine_identity(
    std::array<uint8_t, 32>& identity) const
{
    return copy_identity(
        notification_command::client_id,
        identity);
}

bool client::copy_cpu_disk_identity(
    std::array<uint8_t, 32>& identity) const
{
    return copy_identity(
        notification_command::client_id_v2,
        identity);
}

bool client::copy_tpm_identity(
    std::array<uint8_t, 32>& identity) const
{
    return copy_identity(
        notification_command::client_id_v3,
        identity);
}

bool client::copy_profile_list_identity(
    std::array<uint8_t, 32>& identity) const
{
    return copy_identity(
        notification_command::client_id_v4,
        identity);
}

bool client::copy_file_id_identity(
    std::array<uint8_t, 32>& identity) const
{
    return copy_identity(
        notification_command::client_id_v5,
        identity);
}

sdk_error client::error_code() const noexcept
{
    return error_;
}
}
