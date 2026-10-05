// Secret Service Session management (plain and DH encrypted).
#pragma once

#include "brocred/common.h"
#include "linux/secret_service/crypto_dh.h"

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace brocred::secret_service {

class SecretServiceImpl;

class SecretSession {
public:
    virtual ~SecretSession() = default;

    virtual const std::string& path() const = 0;
    virtual const std::string& algorithm() const = 0;
    virtual bool is_encrypted() const = 0;

    SecretServiceImpl* service() const { return service_; }
    void set_service(SecretServiceImpl* s) { service_ = s; }

    virtual Result encode_secret(const std::string& plaintext,
                                 const std::string& content_type,
                                 std::vector<uint8_t>& out_parameters,
                                 std::vector<uint8_t>& out_value,
                                 std::string& out_content_type) const = 0;

    virtual Result decode_secret(const std::vector<uint8_t>& parameters,
                                 const std::vector<uint8_t>& value,
                                 std::string& out_plaintext) const = 0;

private:
    SecretServiceImpl* service_ = nullptr;
};

class PlainSecretSession : public SecretSession {
public:
    explicit PlainSecretSession(std::string path);
    ~PlainSecretSession() override = default;

    const std::string& path() const override { return path_; }
    const std::string& algorithm() const override;
    bool is_encrypted() const override { return false; }

    Result encode_secret(const std::string& plaintext,
                         const std::string& content_type,
                         std::vector<uint8_t>& out_parameters,
                         std::vector<uint8_t>& out_value,
                         std::string& out_content_type) const override;

    Result decode_secret(const std::vector<uint8_t>& parameters,
                         const std::vector<uint8_t>& value,
                         std::string& out_plaintext) const override;

private:
    std::string path_;
};

class DhSecretSession : public SecretSession {
public:
    DhSecretSession(std::string path, AesKey aes_key);
    ~DhSecretSession() override = default;

    const std::string& path() const override { return path_; }
    const std::string& algorithm() const override;
    bool is_encrypted() const override { return true; }

    Result encode_secret(const std::string& plaintext,
                         const std::string& content_type,
                         std::vector<uint8_t>& out_parameters,
                         std::vector<uint8_t>& out_value,
                         std::string& out_content_type) const override;

    Result decode_secret(const std::vector<uint8_t>& parameters,
                         const std::vector<uint8_t>& value,
                         std::string& out_plaintext) const override;

private:
    std::string path_;
    AesKey aes_key_;
};

class SessionManager {
public:
    SessionManager() = default;
    ~SessionManager() = default;

    // Create a plain session
    std::shared_ptr<SecretSession> open_plain_session(std::string* out_path = nullptr,
                                                      SecretServiceImpl* service = nullptr);

    // Create a DH session negotiating with client public key
    Result open_dh_session(const std::vector<uint8_t>& client_pub,
                           std::vector<uint8_t>& out_server_pub,
                           std::string& out_path,
                           SecretServiceImpl* service = nullptr);

    std::shared_ptr<SecretSession> find_session(const std::string& path) const;
    bool close_session(const std::string& path);
    void clear();

private:
    mutable std::mutex mutex_;
    uint64_t next_id_ = 1;
    std::unordered_map<std::string, std::shared_ptr<SecretSession>> sessions_;
};

}  // namespace brocred::secret_service
