#include "win/win_storage.h"
#include "common/file_keystore.h"
#include "common/memory_keystore.h"

#include <vector>

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

std::string to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int count = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (count <= 1) return "";
    std::string out(count - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, out.data(), count, nullptr, nullptr);
    return out;
}

std::string decode_blob(const BYTE* blob, DWORD size) {
    if (!blob || size == 0) return "";
    // If even number of bytes, attempt UTF-16 decoding (standard for cmdkey / Windows)
    if (size % sizeof(wchar_t) == 0) {
        const wchar_t* wdata = reinterpret_cast<const wchar_t*>(blob);
        size_t wlen = size / sizeof(wchar_t);
        // Trim trailing null if present
        if (wlen > 0 && wdata[wlen - 1] == L'\0') {
            --wlen;
        }
        std::wstring ws(wdata, wlen);
        return to_utf8(ws);
    }
    // Fallback: UTF-8 / ASCII bytes
    return std::string(reinterpret_cast<const char*>(blob), size);
}

std::chrono::system_clock::time_point filetime_to_timepoint(const FILETIME& ft) {
    ULARGE_INTEGER ull;
    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;
    // 100-nanosecond intervals since Jan 1, 1601
    // Difference between 1601 and 1970 is 11644473600 seconds
    constexpr uint64_t kEpochDiff100Ns = 116444736000000000ULL;
    if (ull.QuadPart < kEpochDiff100Ns) return std::chrono::system_clock::now();
    uint64_t unix100Ns = ull.QuadPart - kEpochDiff100Ns;
    uint64_t unixMillis = unix100Ns / 10000;
    return std::chrono::system_clock::time_point(std::chrono::milliseconds(unixMillis));
}

}  // namespace

std::unique_ptr<CredentialStore> CredentialStore::create() {
    return create(StorageOptions());
}

std::unique_ptr<CredentialStore> CredentialStore::create(const StorageOptions& options) {
    switch (options.backend) {
        case BackendType::Memory:
            return std::make_unique<MemoryKeystore>();
        case BackendType::FileKeystore:
            return std::make_unique<FileKeystore>(options.custom_file_path);
        case BackendType::System:
        case BackendType::Auto:
        default:
            return std::make_unique<WinCredStore>();
    }
}

Result WinCredStore::store_secret(const std::string& service, const std::string& account,
                                  const std::string& secret) {
    return store_secret(service, account, secret, {});
}

Result WinCredStore::store_secret(const std::string& service, const std::string& account,
                                  const std::string& secret,
                                  const std::map<std::string, std::string>& attributes) {
    if (service.empty()) {
        return Result::failure("Service name cannot be empty");
    }

    std::wstring target = to_wide(service);
    // If target already exists with a different user and account is non-empty, use service:account
    PCREDENTIALW existing = nullptr;
    if (CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &existing)) {
        std::string existing_user = existing->UserName ? to_utf8(existing->UserName) : "";
        CredFree(existing);
        if (!account.empty() && !existing_user.empty() && existing_user != account) {
            target = to_wide(service + ":" + account);
        }
    }

    std::wstring waccount = to_wide(account);
    std::wstring wsecret = to_wide(secret);

    CREDENTIALW cred{};
    cred.Type = CRED_TYPE_GENERIC;
    cred.TargetName = target.data();
    cred.UserName = account.empty() ? nullptr : waccount.data();
    cred.CredentialBlobSize = static_cast<DWORD>(wsecret.size() * sizeof(wchar_t));
    cred.CredentialBlob = reinterpret_cast<LPBYTE>(wsecret.data());
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE;

    // Build attributes
    std::vector<CREDENTIAL_ATTRIBUTEW> win_attrs;
    std::vector<std::wstring> attr_keys;
    std::vector<std::string> attr_values;
    win_attrs.reserve(attributes.size());
    attr_keys.reserve(attributes.size());
    attr_values.reserve(attributes.size());

    for (const auto& [k, v] : attributes) {
        attr_keys.push_back(to_wide(k));
        attr_values.push_back(v);
        CREDENTIAL_ATTRIBUTEW attr{};
        attr.Keyword = attr_keys.back().data();
        attr.Flags = 0;
        attr.ValueSize = static_cast<DWORD>(attr_values.back().size());
        attr.Value = reinterpret_cast<LPBYTE>(attr_values.back().data());
        win_attrs.push_back(attr);
    }

    if (!win_attrs.empty()) {
        cred.AttributeCount = static_cast<DWORD>(win_attrs.size());
        cred.Attributes = win_attrs.data();
    }

    if (!CredWriteW(&cred, 0)) {
        DWORD err = GetLastError();
        return Result::failure("CredWriteW failed with error code: " + std::to_string(err));
    }

    CredentialChangedEvent ev;
    ev.change = CredentialChangedEvent::ChangeType::Stored;
    ev.service = service;
    ev.account = account;
    events_.push(std::move(ev));

    return Result::success();
}

std::optional<std::string> WinCredStore::read_secret(const std::string& service,
                                                     const std::string& account) {
    auto cred = read_credential(service, account);
    if (!cred) return std::nullopt;
    return cred->secret;
}

std::optional<Credential> WinCredStore::read_credential(const std::string& service,
                                                        const std::string& account) {
    if (service.empty()) return std::nullopt;

    auto try_read = [&](const std::wstring& target_w) -> std::optional<Credential> {
        PCREDENTIALW cred = nullptr;
        if (!CredReadW(target_w.c_str(), CRED_TYPE_GENERIC, 0, &cred) || !cred) {
            return std::nullopt;
        }

        std::string found_user = cred->UserName ? to_utf8(cred->UserName) : "";
        if (!account.empty() && !found_user.empty() && found_user != account) {
            // Target did not match account
            CredFree(cred);
            return std::nullopt;
        }

        Credential c;
        c.service = service;
        c.account = found_user.empty() ? account : found_user;
        c.secret = decode_blob(cred->CredentialBlob, cred->CredentialBlobSize);

        for (DWORD i = 0; i < cred->AttributeCount; ++i) {
            if (cred->Attributes[i].Keyword && cred->Attributes[i].Value) {
                std::string k = to_utf8(cred->Attributes[i].Keyword);
                std::string v(reinterpret_cast<const char*>(cred->Attributes[i].Value),
                              cred->Attributes[i].ValueSize);
                c.attributes[std::move(k)] = std::move(v);
            }
        }

        CredFree(cred);
        return c;
    };

    // First try direct service target
    auto res = try_read(to_wide(service));
    if (res) return res;

    // Fallback: try service:account
    if (!account.empty()) {
        res = try_read(to_wide(service + ":" + account));
        if (res) return res;
    }

    return std::nullopt;
}

Result WinCredStore::delete_secret(const std::string& service, const std::string& account) {
    if (service.empty()) {
        return Result::failure("Service name cannot be empty");
    }

    bool deleted = false;
    std::wstring direct_target = to_wide(service);
    if (CredDeleteW(direct_target.c_str(), CRED_TYPE_GENERIC, 0)) {
        deleted = true;
    }

    if (!account.empty()) {
        std::wstring scoped_target = to_wide(service + ":" + account);
        if (CredDeleteW(scoped_target.c_str(), CRED_TYPE_GENERIC, 0)) {
            deleted = true;
        }
    }

    if (!deleted) {
        DWORD err = GetLastError();
        return Result::failure("CredDeleteW failed with error code: " + std::to_string(err));
    }

    CredentialChangedEvent ev;
    ev.change = CredentialChangedEvent::ChangeType::Deleted;
    ev.service = service;
    ev.account = account;
    events_.push(std::move(ev));

    return Result::success();
}

std::vector<CredentialMetadata> WinCredStore::list_credentials() {
    return list_credentials("");
}

std::vector<CredentialMetadata> WinCredStore::list_credentials(const std::string& service) {
    std::vector<CredentialMetadata> out;
    DWORD count = 0;
    PCREDENTIALW* credentials = nullptr;

    if (!CredEnumerateW(nullptr, 0, &count, &credentials) || !credentials) {
        return out;
    }

    for (DWORD i = 0; i < count; ++i) {
        PCREDENTIALW cred = credentials[i];
        if (!cred || cred->Type != CRED_TYPE_GENERIC || !cred->TargetName) {
            continue;
        }

        std::string target = to_utf8(cred->TargetName);
        std::string user = cred->UserName ? to_utf8(cred->UserName) : "";

        std::string svc = target;
        std::string acc = user;

        size_t colon = target.find(':');
        if (colon != std::string::npos && colon > 0) {
            svc = target.substr(0, colon);
            if (acc.empty()) {
                acc = target.substr(colon + 1);
            }
        }

        if (!service.empty() && svc != service) {
            continue;
        }

        CredentialMetadata meta;
        meta.service = svc;
        meta.account = acc;
        meta.last_modified = filetime_to_timepoint(cred->LastWritten);

        for (DWORD a = 0; a < cred->AttributeCount; ++a) {
            if (cred->Attributes[a].Keyword && cred->Attributes[a].Value) {
                std::string k = to_utf8(cred->Attributes[a].Keyword);
                std::string v(reinterpret_cast<const char*>(cred->Attributes[a].Value),
                              cred->Attributes[a].ValueSize);
                meta.attributes[std::move(k)] = std::move(v);
            }
        }

        out.push_back(std::move(meta));
    }

    CredFree(credentials);
    return out;
}

}  // namespace brocred
