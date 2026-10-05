#include "check.h"
#include "brocred/storage.h"

#include <windows.h>
#include <wincred.h>

#include <cstdio>
#include <memory>
#include <string>

using namespace brocred;

static std::string exec_command(const std::string& cmd) {
    char buffer[256];
    std::string result;
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return "";
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    _pclose(pipe);
    return result;
}

struct OracleCleanup {
    std::string target1;
    std::string user1;
    std::string target2;
    std::string user2;

    ~OracleCleanup() {
        if (!target1.empty()) {
            exec_command("cmdkey /delete:" + target1 + " >nul 2>&1");
        }
        if (!target2.empty()) {
            exec_command("cmdkey /delete:" + target2 + " >nul 2>&1");
        }
    }
};

static void test_cmdkey_roundtrip() {
    OracleCleanup guard;
    guard.target1 = "brocred_oracle_t1";
    guard.user1 = "oracle_user_alpha";
    guard.target2 = "brocred_oracle_t2";
    guard.user2 = "oracle_user_beta";

    // Ensure clean state before starting
    exec_command("cmdkey /delete:" + guard.target1 + " >nul 2>&1");
    exec_command("cmdkey /delete:" + guard.target2 + " >nul 2>&1");

    auto store = CredentialStore::create();
    REQUIRE(store != nullptr);

    // Part 1: brocred writes, cmdkey reads back
    Result r = store->store_secret(guard.target1, guard.user1, "brocred_secret_42");
    CHECK(r.ok);

    std::string list_out = exec_command("cmdkey /list:" + guard.target1);
    CHECK(list_out.find("Target: " + guard.target1) != std::string::npos);
    CHECK(list_out.find("User: " + guard.user1) != std::string::npos);

    // Part 2: cmdkey writes, brocred reads back
    std::string cmdkey_add = "cmdkey /generic:" + guard.target2 +
                             " /user:" + guard.user2 +
                             " /pass:cmdkey_generated_pass_99";
    std::string add_out = exec_command(cmdkey_add);
    CHECK(add_out.find("successfully") != std::string::npos);

    auto read_back = store->read_secret(guard.target2, guard.user2);
    REQUIRE(read_back.has_value());
    CHECK_EQ(*read_back, std::string("cmdkey_generated_pass_99"));

    // Cleanup through brocred delete
    Result del1 = store->delete_secret(guard.target1, guard.user1);
    CHECK(del1.ok);

    Result del2 = store->delete_secret(guard.target2, guard.user2);
    CHECK(del2.ok);

    // Verify deletion via cmdkey /list
    std::string verify_del1 = exec_command("cmdkey /list:" + guard.target1);
    CHECK(verify_del1.find("Target: " + guard.target1) == std::string::npos);

    std::string verify_del2 = exec_command("cmdkey /list:" + guard.target2);
    CHECK(verify_del2.find("Target: " + guard.target2) == std::string::npos);
}

int main() {
    test_cmdkey_roundtrip();
    return bstest::finish("test_win_cmdkey_oracle");
}
