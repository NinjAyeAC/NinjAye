#include "http_client.h"

#include "json_utils.h"

#include <xorstr.hpp>
#include <windows.h>
#include <winhttp.h>

#include <array>
#include <vector>

namespace ninjaye
{
namespace
{
constexpr size_t k_maximum_response_bytes = 4 * 1024 * 1024;

std::wstring join_path(
    const std::wstring& base_path,
    const std::wstring& request_path)
{
    if (base_path.empty() || base_path == xorstr_(L"/"))
    {
        return request_path;
    }

    std::wstring combined = base_path;
    while (!combined.empty() && combined.back() == L'/')
    {
        combined.pop_back();
    }
    if (request_path.empty() || request_path.front() != L'/')
    {
        combined += xorstr_(L"/");
    }
    combined += request_path;
    return combined;
}

std::string query_header(
    HINTERNET request,
    const DWORD query,
    LPCWSTR header_name)
{
    DWORD size = 0;
    if (!WinHttpQueryHeaders(
            request,
            query,
            header_name,
            WINHTTP_NO_OUTPUT_BUFFER,
            &size,
            WINHTTP_NO_HEADER_INDEX) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        return {};
    }
    if (size < sizeof(wchar_t))
    {
        return {};
    }

    std::vector<wchar_t> value(size / sizeof(wchar_t) + 1, L'\0');
    if (!WinHttpQueryHeaders(
            request,
            query,
            header_name,
            value.data(),
            &size,
            WINHTTP_NO_HEADER_INDEX))
    {
        return {};
    }

    size_t length = size / sizeof(wchar_t);
    while (length > 0 && value[length - 1] == L'\0')
    {
        --length;
    }
    return utf8_from_wide(std::wstring(value.data(), length));
}
}

http_response http_post_bytes(
    const std::wstring& base_url,
    const std::string& path,
    const std::vector<uint8_t>& body,
    const std::string& bearer_token,
    const std::string& content_type)
{
    http_response response = {};

    std::array<wchar_t, 256> host = {};
    std::array<wchar_t, 2048> base_path = {};
    URL_COMPONENTS components = {};
    components.dwStructSize = sizeof(components);
    components.lpszHostName = host.data();
    components.dwHostNameLength = static_cast<DWORD>(host.size());
    components.lpszUrlPath = base_path.data();
    components.dwUrlPathLength = static_cast<DWORD>(base_path.size());

    if (!WinHttpCrackUrl(
            base_url.c_str(),
            static_cast<DWORD>(base_url.size()),
            0,
            &components))
    {
        response.error = http_error::invalid_base_url;
        response.native_error = GetLastError();
        return response;
    }

    const std::wstring full_path = join_path(
        std::wstring(base_path.data(), components.dwUrlPathLength),
        wide_from_utf8(path));
    const bool secure = components.nScheme == INTERNET_SCHEME_HTTPS;

    HINTERNET session = WinHttpOpen(
        xorstr_(L"NinjAyeClient/1.0.0"),
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (session == nullptr)
    {
        response.error = http_error::open_failed;
        response.native_error = GetLastError();
        return response;
    }

    int resolve_timeout = 5000;
    int connect_timeout = 5000;
    int send_timeout = 15000;
    int receive_timeout = 30000;
    if (path == xorstr_("/status2.php"))
    {
        resolve_timeout = 2000;
        connect_timeout = 5000;
        send_timeout = 5000;
        receive_timeout = 5000;
    }
    else if (path == xorstr_("/event.php"))
    {
        resolve_timeout = 2000;
        connect_timeout = 2000;
        send_timeout = 2000;
        receive_timeout = 5000;
    }
    else if (path == xorstr_("/upload.php"))
    {
        resolve_timeout = 2000;
        connect_timeout = 2000;
        send_timeout = 5000;
        receive_timeout = 5000;
    }
    else if (path == xorstr_("/file.php"))
    {
        resolve_timeout = 2000;
        connect_timeout = 2000;
        send_timeout = 30000;
        receive_timeout = 10000;
    }
    WinHttpSetTimeouts(
        session,
        resolve_timeout,
        connect_timeout,
        send_timeout,
        receive_timeout);

    DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    WinHttpSetOption(
        session,
        WINHTTP_OPTION_REDIRECT_POLICY,
        &redirect_policy,
        sizeof(redirect_policy));

    HINTERNET connection = WinHttpConnect(
        session,
        std::wstring(host.data(), components.dwHostNameLength).c_str(),
        components.nPort,
        0);
    if (connection == nullptr)
    {
        response.error = http_error::connect_failed;
        response.native_error = GetLastError();
        WinHttpCloseHandle(session);
        return response;
    }

    HINTERNET request = WinHttpOpenRequest(
        connection,
        xorstr_(L"POST"),
        full_path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        secure ? WINHTTP_FLAG_SECURE : 0);
    if (request == nullptr)
    {
        response.error = http_error::create_request_failed;
        response.native_error = GetLastError();
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return response;
    }

    std::wstring headers =
        xorstr_(L"Content-Type: ") +
        wide_from_utf8(content_type) +
        xorstr_(L"\r\n");
    if (!bearer_token.empty())
    {
        headers += xorstr_(L"Authorization: Bearer ");
        headers += wide_from_utf8(bearer_token);
        headers += xorstr_(L"\r\n");
    }

    BOOL sent = WinHttpSendRequest(
        request,
        headers.c_str(),
        static_cast<DWORD>(headers.size()),
        const_cast<uint8_t*>(body.data()),
        static_cast<DWORD>(body.size()),
        static_cast<DWORD>(body.size()),
        0);
    if (!sent)
    {
        response.error = http_error::send_failed;
        response.native_error = GetLastError();
    }
    else if (!WinHttpReceiveResponse(request, nullptr))
    {
        response.error = http_error::receive_failed;
        response.native_error = GetLastError();
    }
    else
    {
        DWORD status_size = sizeof(response.status_code);
        if (!WinHttpQueryHeaders(
            request,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &response.status_code,
            &status_size,
            WINHTTP_NO_HEADER_INDEX))
        {
            response.error = http_error::query_status_failed;
            response.native_error = GetLastError();
        }
        else
        {
            response.transport_ok = true;
            response.content_type = query_header(
                request,
                WINHTTP_QUERY_CONTENT_TYPE,
                WINHTTP_HEADER_NAME_BY_INDEX);
            response.cf_ray = query_header(
                request,
                WINHTTP_QUERY_CUSTOM,
                L"CF-Ray");
            std::array<char, 16 * 1024> buffer = {};
            while (true)
            {
                DWORD available = 0;
                if (!WinHttpQueryDataAvailable(request, &available))
                {
                    response.transport_ok = false;
                    response.error = http_error::query_data_failed;
                    response.native_error = GetLastError();
                    break;
                }
                if (available == 0)
                {
                    break;
                }

                DWORD read = 0;
                const DWORD requested = available > buffer.size()
                    ? static_cast<DWORD>(buffer.size())
                    : available;
                if (!WinHttpReadData(
                        request,
                        buffer.data(),
                        requested,
                        &read))
                {
                    response.transport_ok = false;
                    response.error = http_error::read_failed;
                    response.native_error = GetLastError();
                    break;
                }
                response.body.append(buffer.data(), read);
                if (response.body.size() >
                    k_maximum_response_bytes)
                {
                    response.transport_ok = false;
                    response.error = http_error::response_too_large;
                    break;
                }
            }
        }
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    return response;
}
}
