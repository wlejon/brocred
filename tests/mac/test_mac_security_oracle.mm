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
    bstest::ScopedTestKeychain kc;

    auto store = CredentialStore::create();
    REQUIRE(store != nullptr);

    std::string svc1 = "brocred_mac_oracle_s1";
    std::string acc1 = "mac_oracle_u1";
    std::string svc2 = "brocred_mac_oracle_s2";
    std::string acc2 = "mac_oracle_u2";

    // Part 1: brocred writes, /usr/bin/security reads back
    Result r = store->store_secret(svc1, acc1, "mac_brocred_pass_1");
    CHECK(r.ok);

    std::string sec_read = exec_cmd("/usr/bin/security find-generic-password -s " + svc1 +
                                    " -a " + acc1 + " " + kc.path());
    CHECK(sec_read.find("\"svce\"<blob>=\"" + svc1 + "\"") != std::string::npos);
    CHECK(sec_read.find("\"acct\"<blob>=\"" + acc1 + "\"") != std::string::npos);

    // Part 2: /usr/bin/security writes, brocred reads back
    std::string sec_add = "/usr/bin/security add-generic-password -A -s " + svc2 +
                          " -a " + acc2 + " -w mac_security_pass_2 " + kc.path();
    exec_cmd(sec_add);

    auto read_back = store->read_secret(svc2, acc2);
    REQUIRE(read_back.has_value());
    CHECK_EQ(*read_back, std::string("mac_security_pass_2"));

    // Cleanup
    Result del1 = store->delete_secret(svc1, acc1);
    CHECK(del1.ok);

    Result del2 = store->delete_secret(svc2, acc2);
    CHECK(del2.ok);

    // Verify deletion via security tool
    std::string verify_del = exec_cmd("/usr/bin/security find-generic-password -s " + svc1 +
                                      " -a " + acc1 + " " + kc.path() + " 2>&1");
    CHECK(verify_del.find("could not be found") != std::string::npos);
}

int main() {
    test_mac_security_roundtrip();
    return bstest::finish("test_mac_security_oracle");
}
