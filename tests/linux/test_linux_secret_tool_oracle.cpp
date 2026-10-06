#include "check.h"
#include "brocred/storage.h"

#include <cstdio>
#include <cstdlib>
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

static bool command_available(const std::string& cmd) {
    std::string check = "which " + cmd + " >/dev/null 2>&1";
    return system(check.c_str()) == 0;
}

static void test_secret_tool_roundtrip() {
    if (!command_available("secret-tool")) {
        bstest::skip("test_linux_secret_tool_oracle", "secret-tool is not installed");
    }

    auto store = CredentialStore::create();
    REQUIRE(store != nullptr);

    if (store->backend_name() != "SecretService") {
        bstest::skip("test_linux_secret_tool_oracle",
                     "Secret Service daemon is not running; running under " + store->backend_name());
    }

    std::string test_svc = "brocred_oracle_linux_svc";
    std::string test_acc = "oracle_linux_user";

    // The items land in the user's real keyring: clear them before, and after
    // on every exit path (REQUIRE returns early).
    struct Cleanup {
        std::string cmd;
        explicit Cleanup(std::string c) : cmd(std::move(c)) { exec_cmd(cmd); }
        ~Cleanup() { exec_cmd(cmd); }
    } cleanup("secret-tool clear service " + test_svc + " account " + test_acc + " 2>/dev/null");

    // Part 1: brocred writes, secret-tool reads back
    Result r = store->store_secret(test_svc, test_acc, "oracle_linux_pass_1");
    if (!r.ok || store->backend_name() != "SecretService") {
        bstest::skip("test_linux_secret_tool_oracle",
                     "Cannot store into system Secret Service (keyring locked, prompt required, or fell back): " + r.error);
    }
    CHECK(r.ok);

    std::string lookup_out = exec_cmd("secret-tool lookup service " + test_svc + " account " + test_acc);
    // Trim trailing newline
    while (!lookup_out.empty() && (lookup_out.back() == '\n' || lookup_out.back() == '\r')) {
        lookup_out.pop_back();
    }
    CHECK_EQ(lookup_out, std::string("oracle_linux_pass_1"));

    // Part 2: secret-tool writes, brocred reads back
    std::string store_cmd = "printf 'oracle_tool_pass_2' | secret-tool store --label='Oracle Test' service " +
                            test_svc + " account " + test_acc + " 2>/dev/null";
    exec_cmd(store_cmd);

    auto read_back = store->read_secret(test_svc, test_acc);
    REQUIRE(read_back.has_value());
    CHECK_EQ(*read_back, std::string("oracle_tool_pass_2"));

    store->delete_secret(test_svc, test_acc);
}

int main() {
    bstest::require_mutate("test_linux_secret_tool_oracle");
    test_secret_tool_roundtrip();
    return bstest::finish("test_linux_secret_tool_oracle");
}
