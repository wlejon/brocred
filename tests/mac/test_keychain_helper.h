// Helper for macOS tests to run non-interactively in headless/SSH environments.
#pragma once

#import <Foundation/Foundation.h>
#import <Security/Security.h>

#include <cstdlib>
#include <string>

namespace bstest {

class ScopedTestKeychain {
public:
    ScopedTestKeychain() {
        std::string tmp = "/tmp/brocred_test_" + std::to_string(getpid()) + ".keychain";
        keychain_path_ = tmp;

        // Save original default keychain and search list
        save_current_state();

        // Create and unlock temporary test keychain
        std::string cmd = "rm -f " + keychain_path_ + "; "
                          "/usr/bin/security create-keychain -p test " + keychain_path_ + "; "
                          "/usr/bin/security unlock-keychain -p test " + keychain_path_ + "; "
                          "/usr/bin/security set-keychain-settings " + keychain_path_ + "; "
                          "/usr/bin/security default-keychain -s " + keychain_path_ + "; "
                          "/usr/bin/security list-keychains -s " + keychain_path_;
        int r = system(cmd.c_str());
        (void)r;
    }

    ~ScopedTestKeychain() {
        // Restore default keychain and search list
        if (!orig_default_.empty()) {
            std::string restore = "/usr/bin/security default-keychain -s " + orig_default_;
            system(restore.c_str());
        }
        if (!orig_list_.empty()) {
            std::string restore_list = "/usr/bin/security list-keychains -s " + orig_list_;
            system(restore_list.c_str());
        }
        std::string del = "/usr/bin/security delete-keychain " + keychain_path_ + " 2>/dev/null; "
                          "rm -f " + keychain_path_;
        system(del.c_str());
    }

    const std::string& path() const { return keychain_path_; }

private:
    void save_current_state() {
        FILE* p = popen("/usr/bin/security default-keychain 2>/dev/null", "r");
        if (p) {
            char buf[1024];
            if (fgets(buf, sizeof(buf), p)) {
                std::string s = buf;
                // Trim quotes and whitespace
                size_t start = s.find_first_not_of(" \t\r\n\"");
                size_t end = s.find_last_not_of(" \t\r\n\"");
                if (start != std::string::npos && end != std::string::npos) {
                    orig_default_ = s.substr(start, end - start + 1);
                }
            }
            pclose(p);
        }

        p = popen("/usr/bin/security list-keychains 2>/dev/null", "r");
        if (p) {
            char buf[1024];
            while (fgets(buf, sizeof(buf), p)) {
                std::string s = buf;
                size_t start = s.find_first_not_of(" \t\r\n\"");
                size_t end = s.find_last_not_of(" \t\r\n\"");
                if (start != std::string::npos && end != std::string::npos) {
                    if (!orig_list_.empty()) orig_list_ += " ";
                    orig_list_ += s.substr(start, end - start + 1);
                }
            }
            pclose(p);
        }
    }

    std::string keychain_path_;
    std::string orig_default_;
    std::string orig_list_;
};

}  // namespace bstest
