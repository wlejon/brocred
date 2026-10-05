// Tests for DH Oakley Group 2 key exchange, HKDF, and AES-128-CBC encryption.
#include "check.h"
#include "linux/secret_service/crypto_dh.h"

#include <cstring>

using namespace brocred;
using namespace brocred::secret_service;

static void test_dh_key_exchange_and_aes() {
    // 1. Generate server keypair
    DhOakley2Key server_key;
    REQUIRE(!server_key.public_key().empty());

    // 2. Generate client keypair
    auto client_key = DhOakley2Key::generate();
    REQUIRE(client_key != nullptr);
    REQUIRE(!client_key->public_key().empty());

    // 3. Derive AES keys on both sides
    AesKey server_aes;
    Result r_server = server_key.derive_aes_key(client_key->public_key(), server_aes);
    REQUIRE(r_server.ok);

    AesKey client_aes;
    Result r_client = client_key->derive_aes_key(server_key.public_key(), client_aes);
    REQUIRE(r_client.ok);

    // Both derived keys must match byte-for-byte!
    CHECK_EQ(std::memcmp(server_aes.data, client_aes.data, 16), 0);

    // 4. Test Encryption & Decryption roundtrip
    const std::string test_secret = "SuperSecretPassword123!@#$";
    EncryptedSecret enc;
    Result r_enc = aes_128_cbc_encrypt(client_aes, test_secret, enc);
    REQUIRE(r_enc.ok);
    CHECK_EQ(enc.iv.size(), size_t(16));
    CHECK(!enc.ciphertext.empty());
    CHECK_EQ(enc.ciphertext.size() % 16, size_t(0));

    // Decrypt on server side
    std::string decrypted;
    Result r_dec = aes_128_cbc_decrypt(server_aes, enc.iv, enc.ciphertext, decrypted);
    REQUIRE(r_dec.ok);
    CHECK_EQ(decrypted, test_secret);

    // 5. Encrypt on server side, decrypt on client side
    const std::string response_secret = "AnotherTokenSecretXYZ987654";
    EncryptedSecret resp_enc;
    Result r_resp_enc = aes_128_cbc_encrypt(server_aes, response_secret, resp_enc);
    REQUIRE(r_resp_enc.ok);

    std::string client_decrypted;
    Result r_resp_dec = aes_128_cbc_decrypt(client_aes, resp_enc.iv, resp_enc.ciphertext, client_decrypted);
    REQUIRE(r_resp_dec.ok);
    CHECK_EQ(client_decrypted, response_secret);

    // 6. Corrupted ciphertext test (must fail)
    std::vector<uint8_t> corrupted = enc.ciphertext;
    corrupted.back() ^= 0xFF; // corrupt padding
    std::string bad_out;
    Result r_bad = aes_128_cbc_decrypt(server_aes, enc.iv, corrupted, bad_out);
    CHECK(!r_bad.ok);

    // 7. Invalid IV length test (must fail)
    std::vector<uint8_t> short_iv(12, 0);
    Result r_bad_iv = aes_128_cbc_decrypt(server_aes, short_iv, enc.ciphertext, bad_out);
    CHECK(!r_bad_iv.ok);
}

int main() {
    test_dh_key_exchange_and_aes();
    return bstest::finish("test_crypto_dh");
}
