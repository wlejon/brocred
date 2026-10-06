#include "check.h"
#include "brocred/storage.h"
#include "mac/test_keychain_helper.h"

#include <cstdio>
#include <string>

using namespace brocred;

static std::string exec_cmd(const std::string& cmd) {
    char buffer[256];
    std::string result;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "";
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    pclose(pipe);
    return result;
}

static void test_mac_security_roundtrip() {
    const std::string svc1 = "brocred_mac_oracle_s1";
    const std::string acc1 = "mac_oracle_u1";
    const std::string svc2 = "brocred_mac_oracle_s2";
    const std::string acc2 = "mac_oracle_u2";
    auto temp_kc = bstest::maybe_temp_keychain();
    bstest::ScopedKeychainItems items{{svc1, acc1}, {svc2, acc2}};

    auto store = CredentialStore::create();
    REQUIRE(store != nullptr);

    // Part 1: brocred writes, /usr/bin/security reads the attributes back
    // (not the secret: -w would raise an access prompt for brocred's item).
    Result r = store->store_secret(svc1, acc1, "mac_brocred_pass_1");
    if (!r.ok && bstest::keychain_unavailable(r.error)) {
        bstest::skip("test_mac_security_oracle", "login keychain unavailable in this session: " + r.error +
                                                       bstest::kLockedKeychainHint);
    }
    CHECK(r.ok);

    std::string sec_read = exec_cmd("/usr/bin/security find-generic-password -s " + svc1 + " -a " + acc1);
    CHECK(sec_read.find("\"svce\"<blob>=\"" + svc1 + "\"") != std::string::npos);
    CHECK(sec_read.find("\"acct\"<blob>=\"" + acc1 + "\"") != std::string::npos);

    // Part 2: /usr/bin/security writes (-A: any app may read), brocred reads.
    exec_cmd("/usr/bin/security add-generic-password -A -s " + svc2 + " -a " + acc2 + " -w mac_security_pass_2");

    auto read_back = store->read_secret(svc2, acc2);
    REQUIRE(read_back.has_value());
    CHECK_EQ(*read_back, std::string("mac_security_pass_2"));

    CHECK(store->delete_secret(svc1, acc1).ok);
    CHECK(store->delete_secret(svc2, acc2).ok);

    std::string verify_del = exec_cmd("/usr/bin/security find-generic-password -s " + svc1 + " -a " + acc1 +
                                      " 2>&1");
    CHECK(verify_del.find("could not be found") != std::string::npos);
}

int main() {
    // A temporary keychain is isolated; without one the test writes to the
    // login keychain.
    if (!bstest::opted_in("BROCRED_TEST_TEMP_KEYCHAIN")) bstest::require_mutate("test_mac_security_oracle");
    test_mac_security_roundtrip();
    return bstest::finish("test_mac_security_oracle");
}
