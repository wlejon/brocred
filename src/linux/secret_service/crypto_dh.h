// Diffie-Hellman Oakley Group 2 and AES-128-CBC encryption for Freedesktop Secret Service.
#pragma once

#include "brocred/common.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace brocred::secret_service {

// 128-bit AES key derived from DH exchange
struct AesKey {
    uint8_t data[16] = {0};
};

// Encrypted payload returned by or supplied to Secret Service
struct EncryptedSecret {
    std::vector<uint8_t> iv;          // 16-byte initialization vector (in Secret.parameters)
    std::vector<uint8_t> ciphertext;  // AES-128-CBC encrypted payload (in Secret.value)
};

class DhOakley2Key {
public:
    DhOakley2Key();
    ~DhOakley2Key();

    DhOakley2Key(const DhOakley2Key&) = delete;
    DhOakley2Key& operator=(const DhOakley2Key&) = delete;

    DhOakley2Key(DhOakley2Key&& other) noexcept;
    DhOakley2Key& operator=(DhOakley2Key&& other) noexcept;

    // Returns server public key bytes (big-endian unsigned integer)
    const std::vector<uint8_t>& public_key() const { return public_key_; }

    // Computes shared secret with client public key bytes and derives 128-bit AES key
    Result derive_aes_key(const std::vector<uint8_t>& client_public_key, AesKey& out_key) const;

    // Static helper to create a client keypair (used for tests or client operations)
    static std::unique_ptr<DhOakley2Key> generate();

private:
    struct Impl;
    Impl* impl_ = nullptr;
    std::vector<uint8_t> public_key_;
};

// Encrypt plaintext using AES-128-CBC with PKCS#7 padding
Result aes_128_cbc_encrypt(const AesKey& key,
                           const std::string& plaintext,
                           EncryptedSecret& out_encrypted);

// Decrypt ciphertext using AES-128-CBC and remove PKCS#7 padding
Result aes_128_cbc_decrypt(const AesKey& key,
                           const std::vector<uint8_t>& iv,
                           const std::vector<uint8_t>& ciphertext,
                           std::string& out_plaintext);

}  // namespace brocred::secret_service
