#include "module_classifier.h"

#include "json_utils.h"

#include <windows.h>
#include <wincrypt.h>
#include <mscat.h>
#include <softpub.h>
#include <wintrust.h>

#include <vector>

namespace ninjaye
{
namespace
{
int map_trust_result(const LONG result)
{
    switch (static_cast<DWORD>(result))
    {
    case ERROR_SUCCESS:
        return 2;
    case TRUST_E_NOSIGNATURE:
        return 1;
    case TRUST_E_SUBJECT_FORM_UNKNOWN:
        return 3;
    case TRUST_E_PROVIDER_UNKNOWN:
        return 4;
    case TRUST_E_EXPLICIT_DISTRUST:
        return 5;
    case CERT_E_UNTRUSTEDROOT:
        return 6;
    case TRUST_E_ACTION_UNKNOWN:
        return 7;
    default:
        return 0;
    }
}

std::string signer_name_from_file(const std::wstring& path)
{
    HCERTSTORE store = nullptr;
    HCRYPTMSG message = nullptr;
    DWORD encoding = 0;
    DWORD content = 0;
    DWORD format = 0;
    if (!CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            path.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            &encoding,
            &content,
            &format,
            &store,
            &message,
            nullptr))
    {
        return {};
    }

    DWORD signer_size = 0;
    std::string signer;
    if (CryptMsgGetParam(
            message,
            CMSG_SIGNER_INFO_PARAM,
            0,
            nullptr,
            &signer_size) &&
        signer_size > 0)
    {
        std::vector<unsigned char> bytes(signer_size);
        if (CryptMsgGetParam(
                message,
                CMSG_SIGNER_INFO_PARAM,
                0,
                bytes.data(),
                &signer_size))
        {
            const auto* signer_info =
                reinterpret_cast<CMSG_SIGNER_INFO*>(bytes.data());
            PCCERT_CONTEXT certificate = CertFindCertificateInStore(
                store,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                CERT_FIND_SUBJECT_CERT,
                signer_info,
                nullptr);
            if (certificate != nullptr)
            {
                const DWORD characters = CertGetNameStringW(
                    certificate,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0,
                    nullptr,
                    nullptr,
                    0);
                if (characters > 1)
                {
                    std::vector<wchar_t> name(characters);
                    CertGetNameStringW(
                        certificate,
                        CERT_NAME_SIMPLE_DISPLAY_TYPE,
                        0,
                        nullptr,
                        name.data(),
                        characters);
                    signer = utf8_from_wide(name.data());
                }
                CertFreeCertificateContext(certificate);
            }
        }
    }

    if (message != nullptr)
    {
        CryptMsgClose(message);
    }
    if (store != nullptr)
    {
        CertCloseStore(store, 0);
    }
    return signer;
}

std::string hex_upper(const std::vector<unsigned char>& value)
{
    static const char digits[] = "0123456789ABCDEF";
    std::string output(value.size() * 2, '0');
    for (size_t index = 0; index < value.size(); ++index)
    {
        output[index * 2] = digits[value[index] >> 4];
        output[index * 2 + 1] = digits[value[index] & 0x0F];
    }
    return output;
}

LONG verify_catalog(
    const std::wstring& path,
    LONG previous_result)
{
    if (static_cast<DWORD>(previous_result) != TRUST_E_NOSIGNATURE)
    {
        return previous_result;
    }

    HCATADMIN admin = nullptr;
    if (!CryptCATAdminAcquireContext(&admin, nullptr, 0))
    {
        return previous_result;
    }

    const HANDLE file = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        CryptCATAdminReleaseContext(admin, 0);
        return previous_result;
    }

    DWORD hash_size = 0;
    CryptCATAdminCalcHashFromFileHandle(
        file,
        &hash_size,
        nullptr,
        0);
    std::vector<unsigned char> hash(hash_size);
    const BOOL got_hash = hash_size > 0 &&
        CryptCATAdminCalcHashFromFileHandle(
            file,
            &hash_size,
            hash.data(),
            0);

    HCATINFO catalog = nullptr;
    if (!got_hash)
    {
        CloseHandle(file);
        CryptCATAdminReleaseContext(admin, 0);
        return previous_result;
    }

    catalog = CryptCATAdminEnumCatalogFromHash(
        admin,
        hash.data(),
        hash_size,
        0,
        nullptr);
    if (catalog == nullptr)
    {
        CloseHandle(file);
        CryptCATAdminReleaseContext(admin, 0);
        return static_cast<LONG>(0x800B0100);
    }

    CATALOG_INFO catalog_info = {};
    catalog_info.cbStruct = sizeof(catalog_info);
    if (!CryptCATCatalogInfoFromContext(
            catalog,
            &catalog_info,
            0))
    {
        CloseHandle(file);
        CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
        CryptCATAdminReleaseContext(admin, 0);
        return previous_result;
    }

    const std::string member_tag = hex_upper(hash);
    const std::wstring member_tag_wide(
        member_tag.begin(),
        member_tag.end());

    WINTRUST_CATALOG_INFO catalog_trust = {};
    catalog_trust.cbStruct = sizeof(catalog_trust);
    catalog_trust.pcwszCatalogFilePath = catalog_info.wszCatalogFile;
    catalog_trust.pcwszMemberTag = member_tag_wide.c_str();
    catalog_trust.pcwszMemberFilePath = path.c_str();
    catalog_trust.hMemberFile = file;
    catalog_trust.pbCalculatedFileHash = hash.data();
    catalog_trust.cbCalculatedFileHash = hash_size;
    catalog_trust.hCatAdmin = admin;

    WINTRUST_DATA trust_data = {};
    trust_data.cbStruct = sizeof(trust_data);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_CATALOG;
    trust_data.pCatalog = &catalog_trust;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    trust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG result = WinVerifyTrust(
        nullptr,
        &action,
        &trust_data);
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &trust_data);

    CloseHandle(file);
    CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
    CryptCATAdminReleaseContext(admin, 0);
    return result;
}
}

module_trust classify_module(const std::string& path)
{
    module_trust trust = {};
    const std::wstring wide_path = wide_from_utf8(path);
    if (wide_path.empty())
    {
        trust.result_code = 1;
        return trust;
    }

    WINTRUST_FILE_INFO file_info = {};
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = wide_path.c_str();

    WINTRUST_DATA trust_data = {};
    trust_data.cbStruct = sizeof(trust_data);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.pFile = &file_info;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    trust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG result = WinVerifyTrust(
        nullptr,
        &action,
        &trust_data);

    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &trust_data);

    result = verify_catalog(wide_path, result);
    trust.verified = result == ERROR_SUCCESS;
    trust.result_code = map_trust_result(result);

    if (trust.result_code != 1)
    {
        trust.signer = signer_name_from_file(wide_path);
    }
    return trust;
}
}
