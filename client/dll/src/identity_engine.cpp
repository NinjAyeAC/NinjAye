#include "identity_engine.h"

#include "json_utils.h"

#include <xorstr.hpp>
#include <windows.h>
#include <winioctl.h>
#include <winternl.h>
#include <tbs.h>
#include <userenv.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iterator>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace ninjaye
{
namespace
{
struct cpu_info
{
    uint32_t class_code = 0;
    uint32_t leaf0_eax = 0;
    uint32_t leaf1_eax = 0;
    uint32_t leaf1_edx = 0;
};

struct profile_info
{
    std::wstring path;
    uint32_t creation_high = 0;
    uint32_t creation_low = 0;
    bool available = false;
};

const std::string& alphabet()
{
    static const std::string value =
        xorstr_("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
    return value;
}

cpu_info read_cpu_info()
{
    cpu_info cpu = {};
    std::array<int, 4> leaf0 = {};
    std::array<int, 4> leaf1 = {};
#if defined(_M_IX86) || defined(_M_X64)
    __cpuid(leaf0.data(), 0);
    __cpuid(leaf1.data(), 1);
#endif
    cpu.leaf0_eax = static_cast<uint32_t>(leaf0[0]);
    cpu.leaf1_eax = static_cast<uint32_t>(leaf1[0]);
    cpu.leaf1_edx = static_cast<uint32_t>(leaf1[3]);
    const unsigned char first_vendor_byte =
        static_cast<unsigned char>(
            static_cast<uint32_t>(leaf0[1]) & 0xFF);
    if (first_vendor_byte == 'A')
    {
        cpu.class_code = 1;
    }
    else if (first_vendor_byte == 'G')
    {
        cpu.class_code = 2;
    }
    return cpu;
}

profile_info read_profile_info()
{
    profile_info profile = {};
    HANDLE token = nullptr;
    if (!OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &token))
    {
        return profile;
    }

    DWORD required = 0;
    GetUserProfileDirectoryW(token, nullptr, &required);
    std::vector<wchar_t> path(required + 1);
    if (required > 0 &&
        GetUserProfileDirectoryW(token, path.data(), &required))
    {
        profile.path.assign(path.data(), required);
        WIN32_FILE_ATTRIBUTE_DATA attributes = {};
        if (GetFileAttributesExW(
                profile.path.c_str(),
                GetFileExInfoStandard,
                &attributes))
        {
            profile.creation_high =
                attributes.ftCreationTime.dwHighDateTime;
            profile.creation_low =
                attributes.ftCreationTime.dwLowDateTime;
            profile.available = true;
        }
    }
    CloseHandle(token);
    return profile;
}

uint32_t operating_system_build()
{
    const HMODULE ntdll = GetModuleHandleW(xorstr_(L"ntdll.dll"));
    using rtl_get_version_type = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
    const auto rtl_get_version = reinterpret_cast<rtl_get_version_type>(
        GetProcAddress(ntdll, xorstr_("RtlGetVersion")));
    RTL_OSVERSIONINFOW version = {};
    version.dwOSVersionInfoSize = sizeof(version);
    if (rtl_get_version != nullptr &&
        rtl_get_version(&version) == 0)
    {
        return version.dwBuildNumber;
    }
    return 0;
}

uint64_t physical_memory_mib()
{
    MEMORYSTATUSEX memory = {};
    memory.dwLength = sizeof(memory);
    if (!GlobalMemoryStatusEx(&memory))
    {
        return 0x00000003DAD94000ULL / 1048576ULL;
    }
    return memory.ullTotalPhys / 1048576ULL;
}

std::pair<uint32_t, uint64_t> fixed_drive_summary()
{
    uint32_t count = 0;
    uint64_t total_mib = 0;
    for (wchar_t letter = L'A'; letter <= L'Z'; ++letter)
    {
        std::wstring root = {
            letter,
            L':',
            L'\\',
        };
        if (GetDriveTypeW(root.c_str()) != DRIVE_FIXED)
        {
            continue;
        }

        ++count;
        ULARGE_INTEGER total = {};
        if (GetDiskFreeSpaceExW(
                root.c_str(),
                nullptr,
                &total,
                nullptr))
        {
            total_mib += total.QuadPart / 1048576ULL;
        }
    }
    return {count, total_mib};
}

std::optional<uint64_t> physical_drive_mib()
{
    const HANDLE disk = CreateFileW(
        xorstr_(L"\\\\.\\PhysicalDrive0"),
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);
    if (disk == INVALID_HANDLE_VALUE)
    {
        return std::nullopt;
    }

    std::vector<unsigned char> buffer(4096);
    DWORD returned = 0;
    const BOOL ok = DeviceIoControl(
        disk,
        IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
        nullptr,
        0,
        buffer.data(),
        static_cast<DWORD>(buffer.size()),
        &returned,
        nullptr);
    CloseHandle(disk);
    if (!ok || returned < sizeof(DISK_GEOMETRY_EX))
    {
        return std::nullopt;
    }

    const auto* geometry = reinterpret_cast<const DISK_GEOMETRY_EX*>(
        buffer.data());
    return static_cast<uint64_t>(geometry->DiskSize.QuadPart) /
        1048576ULL;
}

std::string profile_list_prefix(const cpu_info& cpu)
{
    std::ostringstream cpu_text;
    cpu_text << cpu.class_code
        << static_cast<int32_t>(cpu.leaf0_eax)
        << static_cast<int32_t>(cpu.leaf1_eax)
        << static_cast<int32_t>(cpu.leaf1_edx);

    HKEY profiles = nullptr;
    if (RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            xorstr_(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"),
            0,
            KEY_READ,
            &profiles) != ERROR_SUCCESS)
    {
        return {};
    }

    std::wstring selected_prefix;
    for (DWORD index = 0;; ++index)
    {
        wchar_t name[256] = {};
        DWORD name_chars = static_cast<DWORD>(std::size(name));
        if (RegEnumKeyExW(
                profiles,
                index,
                name,
                &name_chars,
                nullptr,
                nullptr,
                nullptr,
                nullptr) != ERROR_SUCCESS)
        {
            break;
        }

        std::wstring key(name);
        if (key.rfind(xorstr_(L"S-1-5-21-"), 0) != 0)
        {
            continue;
        }
        const size_t dash = key.rfind(L'-');
        if (dash == std::wstring::npos)
        {
            continue;
        }

        const wchar_t* suffix_text = key.c_str() + dash + 1;
        wchar_t* end = nullptr;
        const unsigned long suffix = wcstoul(
            suffix_text,
            &end,
            10);
        if (suffix < 1000 || suffix == 0xFFFFFFFFUL)
        {
            continue;
        }
        selected_prefix = key.substr(0, dash);
    }
    RegCloseKey(profiles);

    if (selected_prefix.empty())
    {
        return {};
    }
    return cpu_text.str() + utf8_from_wide(selected_prefix);
}

std::wstring selected_profile_image_path()
{
    HKEY profiles = nullptr;
    if (RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            xorstr_(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"),
            0,
            KEY_READ,
            &profiles) != ERROR_SUCCESS)
    {
        return {};
    }

    std::wstring selected;
    for (DWORD index = 0;; ++index)
    {
        wchar_t name[256] = {};
        DWORD name_chars = static_cast<DWORD>(std::size(name));
        if (RegEnumKeyExW(
                profiles,
                index,
                name,
                &name_chars,
                nullptr,
                nullptr,
                nullptr,
                nullptr) != ERROR_SUCCESS)
        {
            break;
        }
        if (std::wstring(name).rfind(xorstr_(L"S-1-5-21-"), 0) != 0)
        {
            continue;
        }

        HKEY child = nullptr;
        if (RegOpenKeyExW(
                profiles,
                name,
                0,
                KEY_READ,
                &child) != ERROR_SUCCESS)
        {
            continue;
        }

        wchar_t value[1024] = {};
        DWORD bytes = sizeof(value);
        if (RegQueryValueExW(
                child,
                xorstr_(L"ProfileImagePath"),
                nullptr,
                nullptr,
                reinterpret_cast<BYTE*>(value),
                &bytes) == ERROR_SUCCESS)
        {
            selected = value;
        }
        RegCloseKey(child);
    }
    RegCloseKey(profiles);
    return selected;
}

uint64_t file_id_value(const std::wstring& path)
{
    struct file_id_information
    {
        uint64_t volume_serial_number;
        uint64_t file_id_low;
        uint64_t file_id_high;
    };
    using nt_query_information_file_type = NTSTATUS(NTAPI*)(
        HANDLE,
        PIO_STATUS_BLOCK,
        PVOID,
        ULONG,
        ULONG);

    const HMODULE ntdll = GetModuleHandleW(xorstr_(L"ntdll.dll"));
    const auto query_file = reinterpret_cast<
        nt_query_information_file_type>(
            GetProcAddress(
                ntdll,
                xorstr_("NtQueryInformationFile")));
    if (query_file == nullptr)
    {
        return 0;
    }

    const HANDLE file = CreateFileW(
        path.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    IO_STATUS_BLOCK status_block = {};
    file_id_information information = {};
    const NTSTATUS status = query_file(
        file,
        &status_block,
        &information,
        static_cast<ULONG>(sizeof(information)),
        59);
    CloseHandle(file);
    if (status < 0)
    {
        return 0;
    }

    return information.file_id_low;
}

std::vector<std::wstring> identity_file_paths()
{
    wchar_t windows_buffer[MAX_PATH] = {};
    const UINT windows_length = GetWindowsDirectoryW(
        windows_buffer,
        static_cast<UINT>(std::size(windows_buffer)));
    if (windows_length == 0 || windows_length >= std::size(windows_buffer))
    {
        return {};
    }

    const std::wstring windows(windows_buffer);
    const std::wstring profile = selected_profile_image_path();
    return {
        windows + xorstr_(L"\\win.ini"),
        windows + xorstr_(L"\\system.ini"),
        windows + xorstr_(L"\\SysWOW64\\license.rtf"),
        windows + xorstr_(L"\\System32\\drivers\\etc\\services"),
        windows.substr(0, 2) + xorstr_(L"\\Users\\Default\\NTUSER.DAT"),
        profile.empty() ? L"" : profile + xorstr_(L"\\NTUSER.DAT"),
        profile.empty()
            ? L""
            : profile + xorstr_(
                L"\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat"),
        windows + xorstr_(L"\\INF\\oem0.inf"),
    };
}

uint32_t read_be32(const unsigned char* bytes)
{
    return (static_cast<uint32_t>(bytes[0]) << 24) |
        (static_cast<uint32_t>(bytes[1]) << 16) |
        (static_cast<uint32_t>(bytes[2]) << 8) |
        bytes[3];
}

uint16_t read_be16(const unsigned char* bytes)
{
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(bytes[0]) << 8) |
        bytes[1]);
}

std::string tpm_digest_or_default()
{
    const std::string fallback = md5_upper(alphabet());
    TPM_DEVICE_INFO device = {};
    if (Tbsi_GetDeviceInfo(sizeof(device), &device) != TBS_SUCCESS ||
        device.tpmVersion != TPM_VERSION_20)
    {
        return fallback;
    }

    TBS_CONTEXT_PARAMS2 parameters = {};
    parameters.version = TBS_CONTEXT_VERSION_TWO;
    parameters.includeTpm20 = 1;
    TBS_HCONTEXT context = 0;
    if (Tbsi_Context_Create(
            reinterpret_cast<PCTBS_CONTEXT_PARAMS>(&parameters),
            &context) != TBS_SUCCESS)
    {
        return fallback;
    }

    const std::array<unsigned char, 14> command = {
        0x80,
        0x01,
        0x00,
        0x00,
        0x00,
        0x0E,
        0x00,
        0x00,
        0x01,
        0x73,
        0x81,
        0x01,
        0x00,
        0x01,
    };
    std::array<unsigned char, 4096> response = {};
    UINT32 response_size = static_cast<UINT32>(response.size());
    const TBS_RESULT submit = Tbsip_Submit_Command(
        context,
        TBS_COMMAND_LOCALITY_ZERO,
        200,
        command.data(),
        static_cast<UINT32>(command.size()),
        response.data(),
        &response_size);
    Tbsip_Context_Close(context);
    if (submit != TBS_SUCCESS ||
        response_size < 12 ||
        read_be16(response.data()) != 0x8001 ||
        read_be32(response.data() + 6) != 0)
    {
        return fallback;
    }

    const uint32_t total = read_be32(response.data() + 2);
    const uint32_t count = read_be16(response.data() + 10);
    if (total < 12 ||
        total > response_size ||
        count < 64 ||
        count > 2048 ||
        count > total - 12)
    {
        return fallback;
    }

    std::string material = xorstr_("QWTVPRA");
    material.append(
        reinterpret_cast<char*>(response.data() + 12),
        count);
    return md5_upper(material);
}

std::string hex32(const uint32_t value)
{
    std::ostringstream output;
    output << std::hex << std::uppercase << std::setfill('0')
        << std::setw(8) << value;
    return output.str();
}
}

bool collect_identity_snapshot(
    identity_snapshot& snapshot,
    std::string& error)
{
    const cpu_info cpu = read_cpu_info();
    const profile_info profile = read_profile_info();
    const uint32_t build = operating_system_build();
    const uint64_t memory_mib = physical_memory_mib();
    const auto [fixed_count, fixed_mib] = fixed_drive_summary();
    const std::optional<uint64_t> disk_mib = physical_drive_mib();

    if (!profile.available)
    {
        snapshot.client_id = md5_upper(alphabet());
        snapshot.client_id_v2 = md5_upper(alphabet());
    }
    else
    {
        std::ostringstream machine;
        machine << fixed_count
            << fixed_mib
            << build
            << cpu.class_code
            << memory_mib
            << profile.creation_high
            << profile.creation_low;
        snapshot.client_id = md5_upper(machine.str());

        std::ostringstream cpu_disk;
        cpu_disk << cpu.class_code
            << static_cast<int32_t>(cpu.leaf0_eax)
            << static_cast<int32_t>(cpu.leaf1_eax)
            << static_cast<int32_t>(cpu.leaf1_edx);
        if (disk_mib.has_value())
        {
            cpu_disk << disk_mib.value();
        }
        cpu_disk << memory_mib
            << profile.creation_high
            << profile.creation_low;
        snapshot.client_id_v2 = md5_upper(cpu_disk.str());
    }

    snapshot.client_id_v3 = tpm_digest_or_default();

    const std::string sid_material = profile_list_prefix(cpu);
    snapshot.client_id_v4 = sid_material.empty()
        ? md5_upper(alphabet())
        : md5_upper(sid_material);

    std::ostringstream cpu_file_text;
    cpu_file_text << cpu.class_code
        << static_cast<int32_t>(cpu.leaf0_eax)
        << static_cast<int32_t>(cpu.leaf1_eax)
        << static_cast<int32_t>(cpu.leaf1_edx);
    bool required_profile_id = false;
    uint32_t file_count = 0;
    const std::vector<std::wstring> paths = identity_file_paths();
    for (size_t index = 0; index < paths.size(); ++index)
    {
        if (paths[index].empty())
        {
            continue;
        }
        const uint64_t file_id = file_id_value(paths[index]);
        if (file_id == 0)
        {
            continue;
        }
        ++file_count;
        cpu_file_text << index << file_id;
        if (index == 5)
        {
            required_profile_id = true;
        }
    }
    snapshot.client_id_v5 = required_profile_id
        ? md5_upper(cpu_file_text.str())
        : md5_upper(alphabet());

    std::ostringstream sources;
    sources << "{"
        << xorstr_("\"profileAvailable\":")
        << (profile.available ? xorstr_("true") : xorstr_("false")) << ","
        << xorstr_("\"fixedDriveCount\":") << fixed_count << ","
        << xorstr_("\"fixedDriveMiB\":") << fixed_mib << ","
        << xorstr_("\"physicalDriveMiB\":")
        << (disk_mib.has_value() ? std::to_string(disk_mib.value()) : "null")
        << ","
        << xorstr_("\"memoryMiB\":") << memory_mib << ","
        << xorstr_("\"osBuild\":") << build << ","
        << xorstr_("\"cpuClass\":") << cpu.class_code << ","
        << xorstr_("\"cpuLeaf0Eax\":") << json_string(hex32(cpu.leaf0_eax)) << ","
        << xorstr_("\"cpuLeaf1Eax\":") << json_string(hex32(cpu.leaf1_eax)) << ","
        << xorstr_("\"cpuLeaf1Edx\":") << json_string(hex32(cpu.leaf1_edx)) << ","
        << xorstr_("\"profileListSidPrefixPresent\":")
        << (sid_material.empty() ? xorstr_("false") : xorstr_("true")) << ","
        << xorstr_("\"profileFileIdPresent\":")
        << (required_profile_id ? xorstr_("true") : xorstr_("false")) << ","
        << xorstr_("\"identityFileIdCount\":") << file_count
        << "}";
    snapshot.sources_json = sources.str();
    error.clear();
    return true;
}
}
