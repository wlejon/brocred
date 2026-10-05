#include "brocred/verifier.h"

#include <windows.h>
#include <string>

namespace brocred {

namespace {

std::wstring to_wide(const std::string& str) {
    if (str.empty()) return L"";
    int count = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    if (count <= 1) return L"";
    std::wstring out(count - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, out.data(), count);
    return out;
}

std::string get_current_user() {
    wchar_t buf[256];
    DWORD size = 256;
    if (GetUserNameW(buf, &size) && size > 1) {
        int count = WideCharToMultiByte(CP_UTF8, 0, buf, -1, nullptr, 0, nullptr, nullptr);
        if (count > 1) {
            std::string out(count - 1, '\0');
            WideCharToMultiByte(CP_UTF8, 0, buf, -1, out.data(), count, nullptr, nullptr);
            return out;
        }
    }
    return "";
}

std::string win32_error_text(DWORD err) {
    switch (err) {
        case ERROR_LOGON_FAILURE:
            return "Invalid username or password";
        case ERROR_PASSWORD_EXPIRED:
            return "Password expired";
        case ERROR_ACCOUNT_LOCKED_OUT:
            return "Account locked out";
        case ERROR_ACCOUNT_DISABLED:
            return "Account disabled";
        case ERROR_PRIVILEGE_NOT_HELD:
            return "Calling process lacks required logon privilege";
        case ERROR_ACCESS_DENIED:
            return "Access denied";
        default:
            return "LogonUser failed with error code: " + std::to_string(err);
    }
}

}  // namespace

VerifyResult verify_password(const std::string& password) {
    return verify_password("", "", password);
}

VerifyResult verify_password(const std::string& username, const std::string& password) {
    return verify_password(username, "", password);
}

VerifyResult verify_password(const std::string& username, const std::string& domain_or_service,
                             const std::string& password) {
    std::string user = username.empty() ? get_current_user() : username;
    std::string domain = domain_or_service;

    // Check if user contains domain prefix (DOMAIN\user)
    size_t slash = user.find('\\');
    if (slash != std::string::npos) {
        domain = user.substr(0, slash);
        user = user.substr(slash + 1);
    } else {
        // Check if user contains user@domain
        size_t at = user.find('@');
        if (at != std::string::npos) {
            domain = user.substr(at + 1);
            user = user.substr(0, at);
        }
    }

    if (domain.empty()) {
        domain = ".";
    }

    std::wstring wuser = to_wide(user);
    std::wstring wdomain = to_wide(domain);
    std::wstring wpass = to_wide(password);

    HANDLE token = nullptr;
    // Attempt LOGON32_LOGON_NETWORK first (does not require elevated SeBatchLogonRight)
    BOOL ok = LogonUserW(wuser.c_str(), wdomain.c_str(), wpass.c_str(),
                         LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &token);

    if (!ok) {
        DWORD err = GetLastError();
        // If privilege not held or network logon restricted, try INTERACTIVE
        if (err == ERROR_PRIVILEGE_NOT_HELD) {
            ok = LogonUserW(wuser.c_str(), wdomain.c_str(), wpass.c_str(),
                            LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &token);
            if (!ok) {
                err = GetLastError();
            }
        }
        if (!ok) {
            return VerifyResult{false, win32_error_text(err)};
        }
    }

    if (token) {
        CloseHandle(token);
    }
    return VerifyResult{true, ""};
}

}  // namespace brocred
