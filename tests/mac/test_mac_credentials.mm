#include "check.h"
#include "brocred/storage.h"
#include "mac/test_keychain_helper.h"

using namespace brocred;

static void test_mac_cred_crud() {
    const std::string test_svc = "brocred_mac_test_svc";
    const std::string test_acc = "test_user_mac";
    auto temp_kc = bstest::maybe_temp_keychain();
    bstest::ScopedKeychainItems items{{test_svc, test_acc}};

    auto store = CredentialStore::create();
    REQUIRE(store != nullptr);
    CHECK_EQ(store->backend_name(), std::string("AppleKeychain"));

    std::map<std::string, std::string> attrs = {{"os", "darwin"}, {"arch", "arm64"}};
    Result r = store->store_secret(test_svc, test_acc, "mac_secret_key_777", attrs);
    if (!r.ok && bstest::keychain_unavailable(r.error)) {
        bstest::skip("test_mac_credentials", "login keychain unavailable in this session: " + r.error +
                                                   bstest::kLockedKeychainHint);
    }
    CHECK(r.ok);

    auto sec = store->read_secret(test_svc, test_acc);
    REQUIRE(sec.has_value());
    CHECK_EQ(*sec, std::string("mac_secret_key_777"));

    auto cred = store->read_credential(test_svc, test_acc);
    REQUIRE(cred.has_value());
    CHECK_EQ(cred->service, test_svc);
    CHECK_EQ(cred->account, test_acc);
    CHECK_EQ(cred->secret, std::string("mac_secret_key_777"));
    CHECK(cred->attributes.count("os") == 1 && cred->attributes.at("os") == "darwin");
    CHECK(cred->attributes.count("arch") == 1 && cred->attributes.at("arch") == "arm64");

    auto list = store->list_credentials(test_svc);
    REQUIRE(list.size() == 1);
    CHECK_EQ(list[0].service, test_svc);
    CHECK_EQ(list[0].account, test_acc);

    Result del = store->delete_secret(test_svc, test_acc);
    CHECK(del.ok);

    CHECK(!store->read_secret(test_svc, test_acc).has_value());
}

int main() {
    // A temporary keychain is isolated; without one the test writes to the
    // login keychain.
    if (!bstest::opted_in("BROCRED_TEST_TEMP_KEYCHAIN")) bstest::require_mutate("test_mac_credentials");
    test_mac_cred_crud();
    return bstest::finish("test_mac_credentials");
}
