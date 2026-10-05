// Real D-Bus wire protocol tests for Secret Service Provider.
#include "check.h"
#include "brocred/secret_service.h"
#include "linux/dbus/dbus_bus.h"
#include "linux/secret_service/crypto_dh.h"
#include "test_private_bus.h"

#include <systemd/sd-bus.h>

#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>

using namespace brocred;
using namespace brocred::test;
using namespace brocred::secret_service;

static void test_secret_service_plain_and_dh() {
    PrivateBus bus;
    if (!bus.ok()) {
        bstest::skip("test_secret_service", "Failed to start private dbus-daemon");
    }

    SecretServiceOptions opts;
    opts.bus_address = bus.address();
    opts.request_well_known_name = true;
    opts.default_collection_label = "Test Keyring";

    auto provider = SecretServiceProvider::create(opts);
    REQUIRE(provider != nullptr);

    Result start_res = provider->start();
    REQUIRE(start_res.ok);
    CHECK(provider->is_running());

    // Connect client bus connection
    sd_bus* client = nullptr;
    int r = sd_bus_new(&client);
    REQUIRE(r >= 0);
    sd_bus_set_address(client, bus.address().c_str());
    sd_bus_set_bus_client(client, 1);
    r = sd_bus_start(client);
    REQUIRE(r >= 0);

    // =========================================================================
    // Part 1: Test Plain Session
    // =========================================================================
    sd_bus_message* reply = nullptr;
    sd_bus_error err = SD_BUS_ERROR_NULL;

    // OpenSession("plain", "")
    r = sd_bus_call_method(client,
                           "org.freedesktop.secrets",
                           "/org/freedesktop/secrets",
                           "org.freedesktop.Secret.Service",
                           "OpenSession",
                           &err,
                           &reply,
                           "sv",
                           "plain",
                           "s", "");
    REQUIRE(r >= 0);

    const char* plain_sess_path = nullptr;
    r = sd_bus_message_skip(reply, "v");
    REQUIRE(r >= 0);
    r = sd_bus_message_read(reply, "o", &plain_sess_path);
    REQUIRE(r >= 0 && plain_sess_path != nullptr);
    std::string plain_session = plain_sess_path;
    sd_bus_message_unref(reply);

    // Read default collection alias
    r = sd_bus_call_method(client,
                           "org.freedesktop.secrets",
                           "/org/freedesktop/secrets",
                           "org.freedesktop.Secret.Service",
                           "ReadAlias",
                           &err,
                           &reply,
                           "s",
                           "default");
    REQUIRE(r >= 0);
    const char* default_coll_path = nullptr;
    r = sd_bus_message_read(reply, "o", &default_coll_path);
    REQUIRE(r >= 0 && default_coll_path != nullptr);
    std::string default_coll = default_coll_path;
    sd_bus_message_unref(reply);
    CHECK_EQ(default_coll, std::string("/org/freedesktop/secrets/collection/default"));

    // CreateItem in default collection with plain session
    sd_bus_message* m = nullptr;
    r = sd_bus_message_new_method_call(client, &m,
                                       "org.freedesktop.secrets",
                                       default_coll.c_str(),
                                       "org.freedesktop.Secret.Collection",
                                       "CreateItem");
    REQUIRE(r >= 0);

    // properties: label and attributes
    sd_bus_message_open_container(m, 'a', "{sv}");
    sd_bus_message_open_container(m, 'e', "sv");
    sd_bus_message_append(m, "s", "org.freedesktop.Secret.Item.Label");
    sd_bus_message_open_container(m, 'v', "s");
    sd_bus_message_append(m, "s", "TestPlainItem");
    sd_bus_message_close_container(m);
    sd_bus_message_close_container(m);

    sd_bus_message_open_container(m, 'e', "sv");
    sd_bus_message_append(m, "s", "org.freedesktop.Secret.Item.Attributes");
    sd_bus_message_open_container(m, 'v', "a{ss}");
    sd_bus_message_open_container(m, 'a', "{ss}");
    sd_bus_message_append(m, "{ss}", "app", "brotest");
    sd_bus_message_append(m, "{ss}", "user", "alice");
    sd_bus_message_close_container(m);
    sd_bus_message_close_container(m);
    sd_bus_message_close_container(m);
    sd_bus_message_close_container(m);

    // Secret struct: (oayays)
    const std::string plain_pwd = "AliceSecretPlainPassword99";
    sd_bus_message_open_container(m, 'r', "oayays");
    sd_bus_message_append(m, "o", plain_session.c_str());
    sd_bus_message_append_array(m, 'y', nullptr, 0); // parameters empty
    sd_bus_message_append_array(m, 'y', plain_pwd.data(), plain_pwd.size());
    sd_bus_message_append(m, "s", "text/plain");
    sd_bus_message_close_container(m);

    // replace boolean
    sd_bus_message_append(m, "b", 1);

    r = sd_bus_call(client, m, 0, &err, &reply);
    sd_bus_message_unref(m);
    REQUIRE(r >= 0);

    const char* plain_item_path = nullptr;
    const char* prompt_path = nullptr;
    r = sd_bus_message_read(reply, "oo", &plain_item_path, &prompt_path);
    REQUIRE(r >= 0 && plain_item_path != nullptr);
    std::string item1_path = plain_item_path;
    sd_bus_message_unref(reply);

    // Read back secret via GetSecret
    r = sd_bus_call_method(client,
                           "org.freedesktop.secrets",
                           item1_path.c_str(),
                           "org.freedesktop.Secret.Item",
                           "GetSecret",
                           &err,
                           &reply,
                           "o",
                           plain_session.c_str());
    REQUIRE(r >= 0);

    r = sd_bus_message_enter_container(reply, 'r', "oayays");
    REQUIRE(r >= 0);
    const char* ret_sess = nullptr;
    sd_bus_message_read(reply, "o", &ret_sess);
    const void* param_ptr = nullptr;
    size_t param_len = 0;
    sd_bus_message_read_array(reply, 'y', &param_ptr, &param_len);
    const void* val_ptr = nullptr;
    size_t val_len = 0;
    sd_bus_message_read_array(reply, 'y', &val_ptr, &val_len);
    const char* ctype = nullptr;
    sd_bus_message_read(reply, "s", &ctype);
    sd_bus_message_exit_container(reply);

    std::string read_pwd(static_cast<const char*>(val_ptr), val_len);
    CHECK_EQ(read_pwd, plain_pwd);
    CHECK_EQ(std::string(ctype ? ctype : ""), std::string("text/plain"));
    sd_bus_message_unref(reply);

    // =========================================================================
    // Part 2: Test DH Encrypted Session
    // =========================================================================
    auto client_dh = DhOakley2Key::generate();
    REQUIRE(client_dh != nullptr);

    r = sd_bus_message_new_method_call(client, &m,
                                       "org.freedesktop.secrets",
                                       "/org/freedesktop/secrets",
                                       "org.freedesktop.Secret.Service",
                                       "OpenSession");
    REQUIRE(r >= 0);
    sd_bus_message_append(m, "s", "dh-ietf1024-sha256-aes128-cbc-pkcs7");
    sd_bus_message_open_container(m, 'v', "ay");
    sd_bus_message_append_array(m, 'y', client_dh->public_key().data(), client_dh->public_key().size());
    sd_bus_message_close_container(m);

    r = sd_bus_call(client, m, 0, &err, &reply);
    sd_bus_message_unref(m);
    REQUIRE(r >= 0);

    r = sd_bus_message_enter_container(reply, 'v', "ay");
    REQUIRE(r >= 0);
    const void* srv_pub_ptr = nullptr;
    size_t srv_pub_len = 0;
    sd_bus_message_read_array(reply, 'y', &srv_pub_ptr, &srv_pub_len);
    sd_bus_message_exit_container(reply);
    REQUIRE(srv_pub_len > 0);

    const char* dh_sess_path = nullptr;
    sd_bus_message_read(reply, "o", &dh_sess_path);
    REQUIRE(dh_sess_path != nullptr);
    std::string dh_session = dh_sess_path;
    sd_bus_message_unref(reply);

    // Derive client AES key
    std::vector<uint8_t> srv_pub(static_cast<const uint8_t*>(srv_pub_ptr),
                                 static_cast<const uint8_t*>(srv_pub_ptr) + srv_pub_len);
    AesKey client_aes;
    Result dh_derive_res = client_dh->derive_aes_key(srv_pub, client_aes);
    REQUIRE(dh_derive_res.ok);

    // Encrypt secret with client AES key
    const std::string secret_dh_val = "BobTopSecretPayload-42!";
    EncryptedSecret enc_secret;
    Result enc_res = aes_128_cbc_encrypt(client_aes, secret_dh_val, enc_secret);
    REQUIRE(enc_res.ok);

    // Create encrypted item via CreateItem
    r = sd_bus_message_new_method_call(client, &m,
                                       "org.freedesktop.secrets",
                                       default_coll.c_str(),
                                       "org.freedesktop.Secret.Collection",
                                       "CreateItem");
    REQUIRE(r >= 0);

    // Properties
    sd_bus_message_open_container(m, 'a', "{sv}");
    sd_bus_message_open_container(m, 'e', "sv");
    sd_bus_message_append(m, "s", "org.freedesktop.Secret.Item.Label");
    sd_bus_message_open_container(m, 'v', "s");
    sd_bus_message_append(m, "s", "BobEncryptedItem");
    sd_bus_message_close_container(m);
    sd_bus_message_close_container(m);

    sd_bus_message_open_container(m, 'e', "sv");
    sd_bus_message_append(m, "s", "org.freedesktop.Secret.Item.Attributes");
    sd_bus_message_open_container(m, 'v', "a{ss}");
    sd_bus_message_open_container(m, 'a', "{ss}");
    sd_bus_message_append(m, "{ss}", "app", "brotest");
    sd_bus_message_append(m, "{ss}", "user", "bob");
    sd_bus_message_close_container(m);
    sd_bus_message_close_container(m);
    sd_bus_message_close_container(m);
    sd_bus_message_close_container(m);

    // Secret struct: (oayays) with encrypted ciphertext & IV
    sd_bus_message_open_container(m, 'r', "oayays");
    sd_bus_message_append(m, "o", dh_session.c_str());
    sd_bus_message_append_array(m, 'y', enc_secret.iv.data(), enc_secret.iv.size());
    sd_bus_message_append_array(m, 'y', enc_secret.ciphertext.data(), enc_secret.ciphertext.size());
    sd_bus_message_append(m, "s", "text/plain");
    sd_bus_message_close_container(m);
    sd_bus_message_append(m, "b", 1);

    r = sd_bus_call(client, m, 0, &err, &reply);
    sd_bus_message_unref(m);
    REQUIRE(r >= 0);

    const char* dh_item_path = nullptr;
    sd_bus_message_read(reply, "oo", &dh_item_path, &prompt_path);
    REQUIRE(dh_item_path != nullptr);
    std::string item2_path = dh_item_path;
    sd_bus_message_unref(reply);

    // Read back secret using the DH session
    r = sd_bus_call_method(client,
                           "org.freedesktop.secrets",
                           item2_path.c_str(),
                           "org.freedesktop.Secret.Item",
                           "GetSecret",
                           &err,
                           &reply,
                           "o",
                           dh_session.c_str());
    REQUIRE(r >= 0);

    r = sd_bus_message_enter_container(reply, 'r', "oayays");
    REQUIRE(r >= 0);
    const char* dh_ret_sess = nullptr;
    sd_bus_message_read(reply, "o", &dh_ret_sess);
    const void* dh_param_ptr = nullptr;
    size_t dh_param_len = 0;
    sd_bus_message_read_array(reply, 'y', &dh_param_ptr, &dh_param_len);
    const void* dh_val_ptr = nullptr;
    size_t dh_val_len = 0;
    sd_bus_message_read_array(reply, 'y', &dh_val_ptr, &dh_val_len);
    sd_bus_message_read(reply, "s", &ctype);
    sd_bus_message_exit_container(reply);

    std::vector<uint8_t> srv_iv(static_cast<const uint8_t*>(dh_param_ptr),
                                static_cast<const uint8_t*>(dh_param_ptr) + dh_param_len);
    std::vector<uint8_t> srv_cipher(static_cast<const uint8_t*>(dh_val_ptr),
                                    static_cast<const uint8_t*>(dh_val_ptr) + dh_val_len);
    sd_bus_message_unref(reply);

    std::string decrypted_bob_secret;
    Result dec_client_res = aes_128_cbc_decrypt(client_aes, srv_iv, srv_cipher, decrypted_bob_secret);
    REQUIRE(dec_client_res.ok);
    CHECK_EQ(decrypted_bob_secret, secret_dh_val);

    // =========================================================================
    // Part 3: SearchItems and Collection Operations
    // =========================================================================
    r = sd_bus_message_new_method_call(client, &m,
                                       "org.freedesktop.secrets",
                                       "/org/freedesktop/secrets",
                                       "org.freedesktop.Secret.Service",
                                       "SearchItems");
    REQUIRE(r >= 0);
    sd_bus_message_open_container(m, 'a', "{ss}");
    sd_bus_message_append(m, "{ss}", "app", "brotest");
    sd_bus_message_close_container(m);

    r = sd_bus_call(client, m, 0, &err, &reply);
    sd_bus_message_unref(m);
    REQUIRE(r >= 0);

    std::vector<std::string> found_unlocked;
    r = sd_bus_message_enter_container(reply, 'a', "o");
    if (r >= 0) {
        const char* p = nullptr;
        while (sd_bus_message_read(reply, "o", &p) > 0) {
            if (p) found_unlocked.push_back(p);
        }
        sd_bus_message_exit_container(reply);
    }
    sd_bus_message_unref(reply);

    CHECK_EQ(found_unlocked.size(), size_t(2)); // item1 and item2

    // Test Delete Item
    r = sd_bus_call_method(client,
                           "org.freedesktop.secrets",
                           item1_path.c_str(),
                           "org.freedesktop.Secret.Item",
                           "Delete",
                           &err,
                           &reply,
                           "");
    REQUIRE(r >= 0);
    sd_bus_message_unref(reply);

    // Close session
    r = sd_bus_call_method(client,
                           "org.freedesktop.secrets",
                           plain_session.c_str(),
                           "org.freedesktop.Secret.Session",
                           "Close",
                           &err,
                           &reply,
                           "");
    REQUIRE(r >= 0);
    sd_bus_message_unref(reply);

    sd_bus_error_free(&err);
    sd_bus_unref(client);
    provider->stop();
}

int main() {
    test_secret_service_plain_and_dh();
    return bstest::finish("test_secret_service");
}
