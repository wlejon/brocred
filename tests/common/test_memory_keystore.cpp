#include "check.h"
#include "brocred/storage.h"

using namespace brocred;

static void test_crud_and_events() {
    StorageOptions opts;
    opts.backend = BackendType::Memory;
    auto store = CredentialStore::create(opts);
    REQUIRE(store != nullptr);
    CHECK_EQ(store->backend_name(), std::string("Memory"));

    std::map<std::string, std::string> attrs = {{"role", "admin"}, {"env", "staging"}};
    Result r = store->store_secret("com.test.service", "alice", "supersecret123", attrs);
    CHECK(r.ok);

    // Verify events queue received CredentialChangedEvent
    auto events = store->events().drain();
    REQUIRE(events.size() == 1);
    auto* ev = std::get_if<CredentialChangedEvent>(&events[0]);
    REQUIRE(ev != nullptr);
    CHECK(ev->change == CredentialChangedEvent::ChangeType::Stored);
    CHECK_EQ(ev->service, std::string("com.test.service"));
    CHECK_EQ(ev->account, std::string("alice"));

    // Read back secret
    auto sec = store->read_secret("com.test.service", "alice");
    REQUIRE(sec.has_value());
    CHECK_EQ(*sec, std::string("supersecret123"));

    // Read full credential
    auto cred = store->read_credential("com.test.service", "alice");
    REQUIRE(cred.has_value());
    CHECK_EQ(cred->service, std::string("com.test.service"));
    CHECK_EQ(cred->account, std::string("alice"));
    CHECK_EQ(cred->secret, std::string("supersecret123"));
    CHECK_EQ(cred->attributes.size(), size_t(2));
    CHECK_EQ(cred->attributes.at("role"), std::string("admin"));
    CHECK_EQ(cred->attributes.at("env"), std::string("staging"));

    // List credentials
    auto list = store->list_credentials();
    CHECK_EQ(list.size(), size_t(1));
    CHECK_EQ(list[0].service, std::string("com.test.service"));
    CHECK_EQ(list[0].account, std::string("alice"));

    // Filtered list
    auto filtered = store->list_credentials("other.service");
    CHECK(filtered.empty());

    // Delete secret
    Result del_res = store->delete_secret("com.test.service", "alice");
    CHECK(del_res.ok);

    events = store->events().drain();
    REQUIRE(events.size() == 1);
    auto* del_ev = std::get_if<CredentialChangedEvent>(&events[0]);
    REQUIRE(del_ev != nullptr);
    CHECK(del_ev->change == CredentialChangedEvent::ChangeType::Deleted);

    // Verify secret is gone
    sec = store->read_secret("com.test.service", "alice");
    CHECK(!sec.has_value());
    CHECK(store->list_credentials().empty());
}

int main() {
    test_crud_and_events();
    return bstest::finish("test_memory_keystore");
}
