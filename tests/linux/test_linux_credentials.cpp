#include "check.h"
#include "brocred/storage.h"

using namespace brocred;

struct ScopedLinuxCleanup {
    std::string service;
    std::string account;

    ScopedLinuxCleanup(std::string s, std::string a) : service(std::move(s)), account(std::move(a)) {
        cleanup();
    }
    ~ScopedLinuxCleanup() {
        cleanup();
    }
    void cleanup() {
        auto store = CredentialStore::create();
        if (store) {
            store->delete_secret(service, account);
        }
    }
};

static void test_linux_cred_crud() {
    std::string test_svc = "brocred_linux_test_svc";
    std::string test_acc = "test_user_linux";
    ScopedLinuxCleanup guard(test_svc, test_acc);

    auto store = CredentialStore::create();
    REQUIRE(store != nullptr);

    std::map<std::string, std::string> attrs = {{"arch", "x86_64"}, {"distro", "arch"}};
    Result res = store->store_secret(test_svc, test_acc, "linux_pass_1234", attrs);
    CHECK(res.ok);

    auto sec = store->read_secret(test_svc, test_acc);
    REQUIRE(sec.has_value());
    CHECK_EQ(*sec, std::string("linux_pass_1234"));

    auto cred = store->read_credential(test_svc, test_acc);
    REQUIRE(cred.has_value());
    CHECK_EQ(cred->service, test_svc);
    CHECK_EQ(cred->account, test_acc);
    CHECK_EQ(cred->secret, std::string("linux_pass_1234"));
    CHECK_EQ(cred->attributes.at("distro"), std::string("arch"));

    auto list = store->list_credentials(test_svc);
    CHECK_EQ(list.size(), size_t(1));

    Result del = store->delete_secret(test_svc, test_acc);
    CHECK(del.ok);

    CHECK(!store->read_secret(test_svc, test_acc).has_value());
}

int main() {
    test_linux_cred_crud();
    return bstest::finish("test_linux_credentials");
}
