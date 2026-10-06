#include "check.h"
#include "brocred/storage.h"

#include <windows.h>
#include <wincred.h>

using namespace brocred;

struct ScopedCredCleanup {
    std::string service;
    std::string account;

    ScopedCredCleanup(std::string s, std::string a) : service(std::move(s)), account(std::move(a)) {
        cleanup();
    }
    ~ScopedCredCleanup() {
        cleanup();
    }
    void cleanup() {
        auto store = CredentialStore::create();
        if (store) {
            store->delete_secret(service, account);
        }
    }
};

static void test_wincred_crud() {
    std::string test_svc = "brocred_win_test_svc";
    std::string test_acc = "test_user_win";
    ScopedCredCleanup guard(test_svc, test_acc);

    auto store = CredentialStore::create();
    REQUIRE(store != nullptr);
    CHECK_EQ(store->backend_name(), std::string("WindowsCredentialManager"));

    std::map<std::string, std::string> attrs = {{"dept", "engineering"}, {"level", "senior"}};
    Result res = store->store_secret(test_svc, test_acc, "win_p@ssw0rd!", attrs);
    CHECK(res.ok);

    auto sec = store->read_secret(test_svc, test_acc);
    REQUIRE(sec.has_value());
    CHECK_EQ(*sec, std::string("win_p@ssw0rd!"));

    auto cred = store->read_credential(test_svc, test_acc);
    REQUIRE(cred.has_value());
    CHECK_EQ(cred->service, test_svc);
    CHECK_EQ(cred->account, test_acc);
    CHECK_EQ(cred->secret, std::string("win_p@ssw0rd!"));
    CHECK_EQ(cred->attributes.at("dept"), std::string("engineering"));
    CHECK_EQ(cred->attributes.at("level"), std::string("senior"));

    auto list = store->list_credentials(test_svc);
    CHECK_EQ(list.size(), size_t(1));
    CHECK_EQ(list[0].service, test_svc);
    CHECK_EQ(list[0].account, test_acc);

    Result del = store->delete_secret(test_svc, test_acc);
    CHECK(del.ok);

    CHECK(!store->read_secret(test_svc, test_acc).has_value());
}

int main() {
    bstest::require_mutate("test_win_credentials");
    test_wincred_crud();
    return bstest::finish("test_win_credentials");
}
