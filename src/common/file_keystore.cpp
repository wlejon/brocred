#include "common/file_keystore.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace brocred {

namespace {

// Base64 encoder and decoder for safe file serialization of arbitrary strings
static const char kBase64Chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::string& in) {
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(kBase64Chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(kBase64Chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

std::string base64_decode(const std::string& in) {
    std::string out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[static_cast<unsigned char>(kBase64Chars[i])] = i;

    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

}  // namespace

std::string FileKeystore::default_keystore_path() {
#if defined(_WIN32)
    wchar_t local_app_data[MAX_PATH];
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", local_app_data, MAX_PATH) > 0) {
        std::filesystem::path p(local_app_data);
        p /= "brocred";
        p /= "keystore.dat";
        return p.string();
    }
    return "brocred_keystore.dat";
#elif defined(__APPLE__)
    const char* home = std::getenv("HOME");
    if (home) {
        std::filesystem::path p(home);
        p /= "Library";
        p /= "Application Support";
        p /= "brocred";
        p /= "keystore.dat";
        return p.string();
    }
    return "brocred_keystore.dat";
#else
    const char* xdg_data = std::getenv("XDG_DATA_HOME");
    if (xdg_data && *xdg_data) {
        std::filesystem::path p(xdg_data);
        p /= "brocred";
        p /= "keystore.dat";
        return p.string();
    }
    const char* home = std::getenv("HOME");
    if (home) {
        std::filesystem::path p(home);
        p /= ".local";
        p /= "share";
        p /= "brocred";
        p /= "keystore.dat";
        return p.string();
    }
    return "brocred_keystore.dat";
#endif
}

FileKeystore::FileKeystore(std::string file_path) {
    if (file_path.empty()) {
        file_path_ = default_keystore_path();
    } else {
        file_path_ = std::move(file_path);
    }
    load_from_disk();
}

bool FileKeystore::load_from_disk() {
    std::error_code ec;
    if (!std::filesystem::exists(file_path_, ec)) {
        return false;
    }
    std::ifstream file(file_path_);
    if (!file.is_open()) {
        return false;
    }
    std::string line;
    if (!std::getline(file, line) || line != "BROCRED_KEYSTORE_V1") {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    items_.clear();
    timestamps_.clear();

    while (std::getline(file, line)) {
        if (line.empty()) continue;
        std::istringstream iss(line);
        std::string svc_b64, acc_b64, sec_b64;
        uint64_t ts_millis = 0;
        size_t attr_count = 0;

        if (!(iss >> svc_b64 >> acc_b64 >> sec_b64 >> ts_millis >> attr_count)) {
            continue;
        }

        Credential cred;
        cred.service = base64_decode(svc_b64);
        cred.account = base64_decode(acc_b64);
        cred.secret = base64_decode(sec_b64);

        for (size_t i = 0; i < attr_count; ++i) {
            std::string k_b64, v_b64;
            if (iss >> k_b64 >> v_b64) {
                cred.attributes[base64_decode(k_b64)] = base64_decode(v_b64);
            }
        }

        auto key = std::make_pair(cred.service, cred.account);
        items_[key] = std::move(cred);
        timestamps_[key] = std::chrono::system_clock::time_point(
            std::chrono::milliseconds(ts_millis));
    }
    return true;
}

bool FileKeystore::save_to_disk() {
    std::error_code ec;
    std::filesystem::path target_path(file_path_);
    std::filesystem::path parent_dir = target_path.parent_path();
    if (!parent_dir.empty()) {
        std::filesystem::create_directories(parent_dir, ec);
#if !defined(_WIN32)
        ::chmod(parent_dir.c_str(), 0700);
#endif
    }

    std::filesystem::path temp_path = target_path;
    temp_path += ".tmp";

    {
        std::ofstream file(temp_path, std::ios::trunc);
        if (!file.is_open()) {
            return false;
        }

        file << "BROCRED_KEYSTORE_V1\n";
        for (const auto& [key, cred] : items_) {
            auto ts_it = timestamps_.find(key);
            uint64_t ts_ms = 0;
            if (ts_it != timestamps_.end()) {
                ts_ms = static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        ts_it->second.time_since_epoch()).count());
            }

            file << base64_encode(cred.service) << " "
                 << base64_encode(cred.account) << " "
                 << base64_encode(cred.secret) << " "
                 << ts_ms << " "
                 << cred.attributes.size();

            for (const auto& [k, v] : cred.attributes) {
                file << " " << base64_encode(k) << " " << base64_encode(v);
            }
            file << "\n";
        }
    }

#if !defined(_WIN32)
    ::chmod(temp_path.c_str(), 0600);
#endif

    std::filesystem::rename(temp_path, target_path, ec);
    if (ec) {
        // Fallback copy & remove if rename across boundaries fails
        std::filesystem::copy_file(temp_path, target_path,
                                   std::filesystem::copy_options::overwrite_existing, ec);
        std::filesystem::remove(temp_path, ec);
    }
    return !ec;
}

Result FileKeystore::store_secret(const std::string& service, const std::string& account,
                                  const std::string& secret) {
    return store_secret(service, account, secret, {});
}

Result FileKeystore::store_secret(const std::string& service, const std::string& account,
                                  const std::string& secret,
                                  const std::map<std::string, std::string>& attributes) {
    Result res = MemoryKeystore::store_secret(service, account, secret, attributes);
    if (!res) return res;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!save_to_disk()) {
            return Result::failure("Failed to save keystore to disk: " + file_path_);
        }
    }
    return Result::success();
}

Result FileKeystore::delete_secret(const std::string& service, const std::string& account) {
    Result res = MemoryKeystore::delete_secret(service, account);
    if (!res) return res;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!save_to_disk()) {
            return Result::failure("Failed to update keystore on disk: " + file_path_);
        }
    }
    return Result::success();
}

}  // namespace brocred
