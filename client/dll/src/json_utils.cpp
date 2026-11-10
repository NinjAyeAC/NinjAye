#include "json_utils.h"

#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <chrono>
#include <cstdio>
#include <iomanip>
#include <iterator>
#include <objbase.h>
#include <sstream>
#include <vector>

namespace ninjaye
{
namespace
{
std::string file_hash_hex(
    const std::wstring& path,
    const wchar_t* algorithm_name,
    const size_t digest_size)
{
    HANDLE file = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        return {};
    }

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_size = 0;
    DWORD hash_size = 0;
    DWORD result_size = 0;
    std::vector<unsigned char> object;
    std::vector<unsigned char> digest(digest_size);
    bool success = false;

    if (BCryptOpenAlgorithmProvider(
            &algorithm,
            algorithm_name,
            nullptr,
            0) >= 0 &&
        BCryptGetProperty(
            algorithm,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_size),
            sizeof(object_size),
            &result_size,
            0) >= 0 &&
        BCryptGetProperty(
            algorithm,
            BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&hash_size),
            sizeof(hash_size),
            &result_size,
            0) >= 0 &&
        hash_size == digest.size())
    {
        object.resize(object_size);
        if (BCryptCreateHash(
                algorithm,
                &hash,
                object.data(),
                static_cast<ULONG>(object.size()),
                nullptr,
                0,
                0) >= 0)
        {
            std::array<unsigned char, 64 * 1024> buffer = {};
            DWORD read = 0;
            success = true;
            while (ReadFile(
                       file,
                       buffer.data(),
                       static_cast<DWORD>(buffer.size()),
                       &read,
                       nullptr) &&
                read > 0)
            {
                if (BCryptHashData(hash, buffer.data(), read, 0) < 0)
                {
                    success = false;
                    break;
                }
            }
            if (success && BCryptFinishHash(
                    hash,
                    digest.data(),
                    static_cast<ULONG>(digest.size()),
                    0) < 0)
            {
                success = false;
            }
        }
    }

    if (hash != nullptr)
    {
        BCryptDestroyHash(hash);
    }
    if (algorithm != nullptr)
    {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    CloseHandle(file);

    if (!success)
    {
        return {};
    }

    std::ostringstream output;
    output << std::hex << std::uppercase << std::setfill('0');
    for (const unsigned char byte : digest)
    {
        output << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return output.str();
}
}

std::string utf8_from_wide(const std::wstring& value)
{
    if (value.empty())
    {
        return {};
    }

    const int required = WideCharToMultiByte(
        CP_UTF8,
        0,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (required <= 0)
    {
        return {};
    }

    std::string output(static_cast<size_t>(required), '\0');
    WideCharToMultiByte(
        CP_UTF8,
        0,
        value.data(),
        static_cast<int>(value.size()),
        output.data(),
        required,
        nullptr,
        nullptr);
    return output;
}

std::wstring wide_from_utf8(const std::string& value)
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
    if (required <= 0)
    {
        return {};
    }

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

std::string json_escape(std::string_view value)
{
    std::string output;
    output.reserve(value.size() + 16);
    for (const unsigned char character : value)
    {
        switch (character)
        {
        case '"':
            output += "\\\"";
            break;
        case '\\':
            output += "\\\\";
            break;
        case '\b':
            output += "\\b";
            break;
        case '\f':
            output += "\\f";
            break;
        case '\n':
            output += "\\n";
            break;
        case '\r':
            output += "\\r";
            break;
        case '\t':
            output += "\\t";
            break;
        default:
            if (character < 0x20)
            {
                char encoded[7] = {};
                std::snprintf(encoded, sizeof(encoded), "\\u%04X", character);
                output += encoded;
            }
            else
            {
                output.push_back(static_cast<char>(character));
            }
            break;
        }
    }
    return output;
}

std::string json_string(std::string_view value)
{
    return "\"" + json_escape(value) + "\"";
}

std::string current_utc_iso8601()
{
    SYSTEMTIME time = {};
    GetSystemTime(&time);

    char output[40] = {};
    std::snprintf(
        output,
        sizeof(output),
        "%04u-%02u-%02u %02u:%02u:%02u.%03u UTC",
        time.wYear,
        time.wMonth,
        time.wDay,
        time.wHour,
        time.wMinute,
        time.wSecond,
        time.wMilliseconds);
    return output;
}

std::string new_guid_string()
{
    GUID guid = {};
    if (FAILED(CoCreateGuid(&guid)))
    {
        return {};
    }

    wchar_t text[40] = {};
    StringFromGUID2(guid, text, static_cast<int>(std::size(text)));
    std::wstring value(text);
    if (value.size() >= 2 && value.front() == L'{' && value.back() == L'}')
    {
        value = value.substr(1, value.size() - 2);
    }
    return utf8_from_wide(value);
}

std::string sha256_file_hex(const std::wstring& path)
{
    return file_hash_hex(path, BCRYPT_SHA256_ALGORITHM, 32);
}

std::string md5_file_hex(const std::wstring& path)
{
    return file_hash_hex(path, BCRYPT_MD5_ALGORITHM, 16);
}

std::string md5_upper(std::string_view value)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_size = 0;
    DWORD result_size = 0;
    DWORD digest_size = 0;
    std::vector<unsigned char> object;
    std::array<unsigned char, 16> digest = {};
    bool success = false;

    if (BCryptOpenAlgorithmProvider(
            &algorithm,
            BCRYPT_MD5_ALGORITHM,
            nullptr,
            0) >= 0 &&
        BCryptGetProperty(
            algorithm,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_size),
            sizeof(object_size),
            &result_size,
            0) >= 0 &&
        BCryptGetProperty(
            algorithm,
            BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&digest_size),
            sizeof(digest_size),
            &result_size,
            0) >= 0 &&
        digest_size == digest.size())
    {
        object.resize(object_size);
        if (BCryptCreateHash(
                algorithm,
                &hash,
                object.data(),
                static_cast<ULONG>(object.size()),
                nullptr,
                0,
                0) >= 0 &&
            BCryptHashData(
                hash,
                reinterpret_cast<PUCHAR>(
                    const_cast<char*>(value.data())),
                static_cast<ULONG>(value.size()),
                0) >= 0 &&
            BCryptFinishHash(
                hash,
                digest.data(),
                static_cast<ULONG>(digest.size()),
                0) >= 0)
        {
            success = true;
        }
    }

    if (hash != nullptr)
    {
        BCryptDestroyHash(hash);
    }
    if (algorithm != nullptr)
    {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    if (!success)
    {
        return {};
    }

    std::ostringstream output;
    output << std::hex << std::uppercase << std::setfill('0');
    for (const unsigned char byte : digest)
    {
        output << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return output.str();
}

std::string extract_json_string(
    const std::string& json,
    std::string_view key)
{
    const std::string marker = "\"" + std::string(key) + "\"";
    const size_t key_position = json.find(marker);
    if (key_position == std::string::npos)
    {
        return {};
    }

    const size_t colon = json.find(':', key_position + marker.size());
    if (colon == std::string::npos)
    {
        return {};
    }

    const size_t quote = json.find('"', colon + 1);
    if (quote == std::string::npos)
    {
        return {};
    }

    std::string output;
    bool escaped = false;
    for (size_t index = quote + 1; index < json.size(); ++index)
    {
        const char character = json[index];
        if (escaped)
        {
            output.push_back(character);
            escaped = false;
            continue;
        }
        if (character == '\\')
        {
            escaped = true;
            continue;
        }
        if (character == '"')
        {
            return output;
        }
        output.push_back(character);
    }
    return {};
}

std::string read_computer_name()
{
    wchar_t name[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD size = static_cast<DWORD>(std::size(name));
    if (!GetComputerNameW(name, &size))
    {
        return {};
    }
    return utf8_from_wide(std::wstring(name, size));
}

std::string read_user_name()
{
    wchar_t name[256] = {};
    DWORD size = static_cast<DWORD>(std::size(name));
    if (!GetUserNameW(name, &size))
    {
        return {};
    }
    return utf8_from_wide(
        std::wstring(name, size > 0 ? size - 1 : 0));
}
}
