#include "check.h"
#include "brocred/secret_service.h"
#include "linux/dbus/dbus_bus.h"
#include "test_private_bus.h"

#include <systemd/sd-bus.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

using namespace brocred;
using namespace brocred::test;
using namespace brocred::linux_dbus;

static void test_real_secret_service_client() {
    PrivateBus bus;
    if (!bus.ok()) {
        bstest::skip("test_linux_dbus_client", "Failed to start private dbus-daemon");
        return;
    }

    // Start real Secret Service provider on private bus
    SecretServiceOptions opts;
    opts.bus_address = bus.address();
    opts.request_well_known_name = true;
    opts.default_collection_label = "Test Keyring";

    auto provider = SecretServiceProvider::create(opts);
    REQUIRE(provider != nullptr);
    Result r = provider->start();
    REQUIRE(r.ok);
    CHECK(provider->is_running());

    // Client connects to the real provider over private bus
    auto client = BusConnection::open(BusType::Address, bus.address());
    REQUIRE(client != nullptr && client->valid());
    CHECK(client->has_owner("org.freedesktop.secrets"));

    // 1. OpenSession
    std::string session_path;
    std::string err;
    bool ok = client->secret_service_open_session(session_path, &err);
    CHECK(ok);
    CHECK(!session_path.empty());

    // 2. CreateItem
    std::string created_item;
    std::map<std::string, std::string> attrs = {{"service", "testsvc"}, {"account", "testuser"}};
    ok = client->secret_service_create_item("", session_path, "Test Label", attrs,
                                            "my_secret_token_123", true, created_item, &err);
    CHECK(ok);
    CHECK(!created_item.empty());

    // 3. SearchItems
    std::vector<std::string> unlocked, locked;
    ok = client->secret_service_search_items(attrs, unlocked, locked, &err);
    CHECK(ok);
    REQUIRE(!unlocked.empty());
    CHECK_EQ(unlocked[0], created_item);

    // 4. GetSecret
    std::string secret_val;
    ok = client->secret_service_get_secret(unlocked[0], session_path, secret_val, &err);
    CHECK(ok);
    CHECK_EQ(secret_val, std::string("my_secret_token_123"));

    // 5. Delete
    ok = client->secret_service_delete_item(unlocked[0], &err);
    CHECK(ok);

    // 6. Verify item is gone
    unlocked.clear();
    locked.clear();
    ok = client->secret_service_search_items(attrs, unlocked, locked, &err);
    CHECK(ok);
    CHECK(unlocked.empty() && locked.empty());

    provider->stop();
}

int main() {
    test_real_secret_service_client();
    return bstest::finish("test_linux_dbus_client");
}
