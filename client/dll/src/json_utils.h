#ifndef NINJAYE_JSON_UTILS_H
#define NINJAYE_JSON_UTILS_H

#include <string>
#include <string_view>

namespace ninjaye
{
std::string utf8_from_wide(const std::wstring& value);

std::wstring wide_from_utf8(const std::string& value);

std::string json_escape(std::string_view value);

std::string json_string(std::string_view value);

std::string current_utc_iso8601();

std::string new_guid_string();

std::string sha256_file_hex(const std::wstring& path);

std::string md5_file_hex(const std::wstring& path);

std::string md5_upper(std::string_view value);

std::string extract_json_string(
    const std::string& json,
    std::string_view key);

std::string read_computer_name();

std::string read_user_name();
}

#endif
