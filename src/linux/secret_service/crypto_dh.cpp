// Implementation of DH Oakley Group 2 key exchange, HKDF-SHA256, and AES-128-CBC.
#include "linux/secret_service/crypto_dh.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <cstring>
#include <memory>

namespace brocred::secret_service {

namespace {

// RFC 2409 Second Oakley Group (1024-bit MODP prime):
// 2^1024 - 2^960 - 1 + 2^64 * { [2^894 pi] + 129097 }
const unsigned char kOakley2Prime[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
    0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
    0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
    0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
    0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
    0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

constexpr int kOakley2PrimeBytes = 128; // 1024 bits

struct BnCtxDeleter {
    void operator()(BN_CTX* ctx) const { if (ctx) BN_CTX_free(ctx); }
};
struct BnDeleter {
    void operator()(BIGNUM* bn) const { if (bn) BN_free(bn); }
};
struct CipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const { if (ctx) EVP_CIPHER_CTX_free(ctx); }
};

using ScopedBnCtx = std::unique_ptr<BN_CTX, BnCtxDeleter>;
using ScopedBn = std::unique_ptr<BIGNUM, BnDeleter>;
using ScopedCipherCtx = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;

}  // namespace

struct DhOakley2Key::Impl {
    ScopedBn prime;
    ScopedBn generator;
    ScopedBn private_key;
    ScopedBn public_key;

    Impl() {
        prime.reset(BN_bin2bn(kOakley2Prime, sizeof(kOakley2Prime), nullptr));
        generator.reset(BN_new());
        if (generator) BN_set_word(generator.get(), 2);
        private_key.reset(BN_new());
        public_key.reset(BN_new());
    }
};

DhOakley2Key::DhOakley2Key() : impl_(new Impl()) {
    ScopedBnCtx ctx(BN_CTX_new());
    if (!ctx || !impl_->prime || !impl_->generator || !impl_->private_key || !impl_->public_key) {
        return;
    }

    // Generate random 1024-bit private key in range [1, prime - 1]
    if (BN_rand_range(impl_->private_key.get(), impl_->prime.get()) <= 0) {
        return;
    }

    // public_key = generator ^ private_key mod prime
    if (BN_mod_exp(impl_->public_key.get(),
                   impl_->generator.get(),
                   impl_->private_key.get(),
                   impl_->prime.get(),
                   ctx.get()) <= 0) {
        return;
    }

    int bytes = BN_num_bytes(impl_->public_key.get());
    public_key_.resize(bytes);
    BN_bn2bin(impl_->public_key.get(), public_key_.data());
}

DhOakley2Key::~DhOakley2Key() {
    delete impl_;
    impl_ = nullptr;
}

DhOakley2Key::DhOakley2Key(DhOakley2Key&& other) noexcept
    : impl_(other.impl_), public_key_(std::move(other.public_key_)) {
    other.impl_ = nullptr;
}

DhOakley2Key& DhOakley2Key::operator=(DhOakley2Key&& other) noexcept {
    if (this != &other) {
        delete impl_;
        impl_ = other.impl_;
        public_key_ = std::move(other.public_key_);
        other.impl_ = nullptr;
    }
    return *this;
}

std::unique_ptr<DhOakley2Key> DhOakley2Key::generate() {
    auto key = std::make_unique<DhOakley2Key>();
    if (key->public_key().empty()) {
        return nullptr;
    }
    return key;
}

Result DhOakley2Key::derive_aes_key(const std::vector<uint8_t>& client_public_key,
                                   AesKey& out_key) const {
    if (!impl_ || !impl_->prime || !impl_->private_key) {
        return Result::failure("DH key uninitialized");
    }
    if (client_public_key.empty()) {
        return Result::failure("Client public key is empty");
    }

    ScopedBnCtx ctx(BN_CTX_new());
    if (!ctx) {
        return Result::failure("Failed to allocate BIGNUM context");
    }

    ScopedBn client_pub(BN_bin2bn(client_public_key.data(),
                                  static_cast<int>(client_public_key.size()),
                                  nullptr));
    if (!client_pub) {
        return Result::failure("Failed to parse client public key");
    }

    // shared_secret = client_pub ^ private_key mod prime
    ScopedBn shared_secret(BN_new());
    if (BN_mod_exp(shared_secret.get(),
                   client_pub.get(),
                   impl_->private_key.get(),
                   impl_->prime.get(),
                   ctx.get()) <= 0) {
        return Result::failure("DH key exchange computation failed");
    }

    // Export shared secret to 128 bytes big-endian
    uint8_t secret_bytes[kOakley2PrimeBytes] = {0};
    if (BN_bn2binpad(shared_secret.get(), secret_bytes, kOakley2PrimeBytes) <= 0) {
        return Result::failure("Failed to format shared secret bytes");
    }

    // HKDF (RFC 5869) as specified in Secret Service API:
    // Extract: PRK = HMAC-SHA256(salt=0x00*32, IKM=secret_bytes)
    const uint8_t zero_salt[32] = {0};
    uint8_t prk[32] = {0};
    unsigned int prk_len = 0;
    if (!HMAC(EVP_sha256(), zero_salt, sizeof(zero_salt),
              secret_bytes, sizeof(secret_bytes),
              prk, &prk_len)) {
        return Result::failure("HMAC-SHA256 HKDF-Extract failed");
    }

    // Expand: OKM = HMAC-SHA256(PRK, info="\x01")
    const uint8_t info[] = {0x01};
    uint8_t okm[32] = {0};
    unsigned int okm_len = 0;
    if (!HMAC(EVP_sha256(), prk, prk_len,
              info, sizeof(info),
              okm, &okm_len)) {
        return Result::failure("HMAC-SHA256 HKDF-Expand failed");
    }

    // Secret Service uses 128-bit (16-byte) AES key from first 16 bytes of OKM
    std::memcpy(out_key.data, okm, 16);
    return Result::success();
}

Result aes_128_cbc_encrypt(const AesKey& key,
                           const std::string& plaintext,
                           EncryptedSecret& out_encrypted) {
    out_encrypted.iv.resize(16);
    if (RAND_bytes(out_encrypted.iv.data(), 16) <= 0) {
        return Result::failure("Failed to generate random IV");
    }

    ScopedCipherCtx ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        return Result::failure("Failed to allocate cipher context");
    }

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_cbc(), nullptr, key.data, out_encrypted.iv.data()) <= 0) {
        return Result::failure("EVP_EncryptInit_ex failed");
    }

    // OpenSSL enables PKCS#7 padding by default
    EVP_CIPHER_CTX_set_padding(ctx.get(), 1);

    out_encrypted.ciphertext.resize(plaintext.size() + 16);
    int len1 = 0;
    if (EVP_EncryptUpdate(ctx.get(),
                          out_encrypted.ciphertext.data(),
                          &len1,
                          reinterpret_cast<const unsigned char*>(plaintext.data()),
                          static_cast<int>(plaintext.size())) <= 0) {
        return Result::failure("EVP_EncryptUpdate failed");
    }

    int len2 = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), out_encrypted.ciphertext.data() + len1, &len2) <= 0) {
        return Result::failure("EVP_EncryptFinal_ex failed");
    }

    out_encrypted.ciphertext.resize(len1 + len2);
    return Result::success();
}

Result aes_128_cbc_decrypt(const AesKey& key,
                           const std::vector<uint8_t>& iv,
                           const std::vector<uint8_t>& ciphertext,
                           std::string& out_plaintext) {
    if (iv.size() != 16) {
        return Result::failure("Invalid IV size (expected 16 bytes)");
    }
    if (ciphertext.empty() || (ciphertext.size() % 16) != 0) {
        return Result::failure("Invalid ciphertext size (must be non-empty multiple of 16)");
    }

    ScopedCipherCtx ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        return Result::failure("Failed to allocate cipher context");
    }

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_cbc(), nullptr, key.data, iv.data()) <= 0) {
        return Result::failure("EVP_DecryptInit_ex failed");
    }

    EVP_CIPHER_CTX_set_padding(ctx.get(), 1);

    std::vector<uint8_t> plain(ciphertext.size());
    int len1 = 0;
    if (EVP_DecryptUpdate(ctx.get(),
                          plain.data(),
                          &len1,
                          ciphertext.data(),
                          static_cast<int>(ciphertext.size())) <= 0) {
        return Result::failure("EVP_DecryptUpdate failed");
    }

    int len2 = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), plain.data() + len1, &len2) <= 0) {
        return Result::failure("EVP_DecryptFinal_ex failed: invalid padding or corrupted ciphertext");
    }

    plain.resize(len1 + len2);
    out_plaintext.assign(reinterpret_cast<const char*>(plain.data()), plain.size());
    return Result::success();
}

}  // namespace brocred::secret_service
