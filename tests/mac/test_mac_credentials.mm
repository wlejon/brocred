#include "check.h"
#include "brocred/storage.h"
#include "mac/test_keychain_helper.h"

using namespace brocred;

static void test_mac_cred_crud() {
    bstest::ScopedTestKeychain kc;

    auto store = CredentialStore::create();
    REQUIRE(store != nullptr);
    CHECK_EQ(store->backend_name(), std::string("AppleKeychain"));

    std::string test_svc = "brocred_mac_test_svc";
    std::string test_acc = "test_user_mac";

    std::map<std::string, std::string> attrs = {{"os", "darwin"}, {"arch", "arm64"}};
    Result r = store->store_secret(test_svc, test_acc, "mac_secret_key_777", attrs);
    CHECK(r.ok);

    auto sec = store->read_secret(test_svc, test_acc);
    REQUIRE(sec.has_value());
    CHECK_EQ(*sec, std::string("mac_secret_key_777"));

    auto cred = store->read_credential(test_svc, test_acc);
    REQUIRE(cred.has_value());
    CHECK_EQ(cred->service, test_svc);
    CHECK_EQ(cred->account, test_acc);
    CHECK_EQ(cred->secret, std::string("mac_secret_key_777"));
    CHECK_EQ(cred->attributes.at("os"), std::string("darwin"));
    CHECK_EQ(cred->attributes.at("arch"), std::string("arm64"));

    auto list = store->list_credentials(test_svc);
    CHECK_EQ(list.size(), size_t(1));
    CHECK_EQ(list[0].service, test_svc);
    CHECK_EQ(list[0].account, test_acc);

    Result del = store->delete_secret(test_svc, test_acc);
    CHECK(del.ok);

    CHECK(!store->read_secret(test_svc, test_acc).has_value());
}

int main() {
    test_mac_cred_crud();
    return bstest::finish("test_mac_credentials");
}
