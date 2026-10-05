// Helper for the macOS keychain tests.
//
// The tests use the user's real default keychain and never change keychain
// settings (an earlier version swapped the default keychain and search list
// for a temporary one; a test killed mid-run left the user's apps pointing at
// a deleted keychain). Every item a test may create is registered here and
// deleted before the test starts and again on every exit path. Only
// attributes are read through /usr/bin/security (no -w), so no access prompt
// appears.
#pragma once

#import <Foundation/Foundation.h>
#import <Security/Security.h>

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

namespace bstest {

class ScopedKeychainItems {
public:
    ScopedKeychainItems(std::initializer_list<std::pair<std::string, std::string>> items)
        : items_(items) {
        remove_all();
    }
    ~ScopedKeychainItems() { remove_all(); }

    ScopedKeychainItems(const ScopedKeychainItems&) = delete;
    ScopedKeychainItems& operator=(const ScopedKeychainItems&) = delete;

private:
    void remove_all() {
        for (const auto& [service, account] : items_) {
            // Deletes every matching generic password, in any keychain on the
            // search list.
            NSDictionary* query = @{
                (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                (__bridge id)kSecAttrService: [NSString stringWithUTF8String:service.c_str()],
                (__bridge id)kSecAttrAccount: [NSString stringWithUTF8String:account.c_str()],
                (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
            };
            SecItemDelete((__bridge CFDictionaryRef)query);
            // Items added by /usr/bin/security belong to that tool's ACL; let
            // it remove whatever SecItemDelete could not.
            for (int i = 0; i < 4; ++i) {
                std::string cmd = "/usr/bin/security delete-generic-password -s '" + service + "' -a '" +
                                  account + "' >/dev/null 2>&1";
                if (std::system(cmd.c_str()) != 0) break;
            }
        }
    }

    std::vector<std::pair<std::string, std::string>> items_;
};

// Opt-in (BROCRED_TEST_TEMP_KEYCHAIN=1) for sessions whose login keychain is
// locked, such as SSH on a build Mac: makes an unlocked temporary keychain
// the default and only searched keychain for the duration of the test, then
// restores the previous default and search list. This rewrites the user's
// keychain preferences while it runs, and a test killed mid-run leaves them
// pointing at a deleted keychain, which is why it is not the default.
class ScopedTempDefaultKeychain {
public:
    ScopedTempDefaultKeychain() {
        path_ = "/tmp/brocred_test_" + std::to_string(getpid()) + ".keychain";
        orig_default_ = read_lines("/usr/bin/security default-keychain -d user 2>/dev/null");
        orig_list_ = read_lines("/usr/bin/security list-keychains -d user 2>/dev/null");
        run("rm -f " + q(path_));
        run("/usr/bin/security create-keychain -p test " + q(path_));
        run("/usr/bin/security unlock-keychain -p test " + q(path_));
        run("/usr/bin/security set-keychain-settings " + q(path_));
        run("/usr/bin/security default-keychain -d user -s " + q(path_));
        run("/usr/bin/security list-keychains -d user -s " + q(path_));
    }
    ~ScopedTempDefaultKeychain() {
        if (!orig_default_.empty()) run("/usr/bin/security default-keychain -d user -s " + q(orig_default_[0]));
        std::string list = "/usr/bin/security list-keychains -d user -s";
        for (const auto& k : orig_list_) list += " " + q(k);
        run(list);
        run("/usr/bin/security delete-keychain " + q(path_) + " 2>/dev/null; rm -f " + q(path_));
    }
    ScopedTempDefaultKeychain(const ScopedTempDefaultKeychain&) = delete;
    ScopedTempDefaultKeychain& operator=(const ScopedTempDefaultKeychain&) = delete;

private:
    static std::string q(const std::string& s) { return "'" + s + "'"; }
    static void run(const std::string& cmd) { (void)std::system(cmd.c_str()); }
    static std::vector<std::string> read_lines(const char* cmd) {
        std::vector<std::string> out;
        FILE* p = popen(cmd, "r");
        if (!p) return out;
        char buf[1024];
        while (fgets(buf, sizeof(buf), p)) {
            std::string s = buf;
            size_t a = s.find_first_not_of(" \t\r\n\"");
            size_t b = s.find_last_not_of(" \t\r\n\"");
            if (a != std::string::npos) out.push_back(s.substr(a, b - a + 1));
        }
        pclose(p);
        return out;
    }

    std::string path_;
    std::vector<std::string> orig_default_;
    std::vector<std::string> orig_list_;
};

// errSecInteractionNotAllowed / errSecNoSuchKeychain and friends: the login
// keychain is locked or absent (e.g. an SSH session with no GUI login).
inline std::unique_ptr<ScopedTempDefaultKeychain> maybe_temp_keychain() {
    if (!opted_in("BROCRED_TEST_TEMP_KEYCHAIN")) return nullptr;
    return std::make_unique<ScopedTempDefaultKeychain>();
}

inline const char* kLockedKeychainHint =
    " (set BROCRED_TEST_TEMP_KEYCHAIN=1 to run against a temporary keychain instead)";

inline bool keychain_unavailable(const std::string& error) {
    return error.find("-25308") != std::string::npos || error.find("-25294") != std::string::npos ||
           error.find("-25307") != std::string::npos || error.find("nteraction") != std::string::npos ||
           error.find("locked") != std::string::npos;
}

}  // namespace bstest
