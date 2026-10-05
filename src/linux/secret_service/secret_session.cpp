// Implementation of Secret Service sessions.
#include "linux/secret_service/secret_session.h"

namespace brocred::secret_service {

namespace {
const std::string kPlainAlgorithm = "plain";
const std::string kDhAlgorithm = "dh-ietf1024-sha256-aes128-cbc-pkcs7";
const std::string kDefaultContentType = "text/plain";
}  // namespace

// PlainSecretSession
PlainSecretSession::PlainSecretSession(std::string path) : path_(std::move(path)) {}

const std::string& PlainSecretSession::algorithm() const {
    return kPlainAlgorithm;
}

Result PlainSecretSession::encode_secret(const std::string& plaintext,
                                        const std::string& content_type,
                                        std::vector<uint8_t>& out_parameters,
                                        std::vector<uint8_t>& out_value,
                                        std::string& out_content_type) const {
    out_parameters.clear();
    out_value.assign(reinterpret_cast<const uint8_t*>(plaintext.data()),
                     reinterpret_cast<const uint8_t*>(plaintext.data() + plaintext.size()));
    out_content_type = content_type.empty() ? kDefaultContentType : content_type;
    return Result::success();
}

Result PlainSecretSession::decode_secret(const std::vector<uint8_t>& /*parameters*/,
                                        const std::vector<uint8_t>& value,
                                        std::string& out_plaintext) const {
    out_plaintext.assign(reinterpret_cast<const char*>(value.data()), value.size());
    return Result::success();
}

// DhSecretSession
DhSecretSession::DhSecretSession(std::string path, AesKey aes_key)
    : path_(std::move(path)), aes_key_(aes_key) {}

const std::string& DhSecretSession::algorithm() const {
    return kDhAlgorithm;
}

Result DhSecretSession::encode_secret(const std::string& plaintext,
                                     const std::string& content_type,
                                     std::vector<uint8_t>& out_parameters,
                                     std::vector<uint8_t>& out_value,
                                     std::string& out_content_type) const {
    EncryptedSecret enc;
    Result r = aes_128_cbc_encrypt(aes_key_, plaintext, enc);
    if (!r.ok) {
        return r;
    }
    out_parameters = std::move(enc.iv);
    out_value = std::move(enc.ciphertext);
    out_content_type = content_type.empty() ? kDefaultContentType : content_type;
    return Result::success();
}

Result DhSecretSession::decode_secret(const std::vector<uint8_t>& parameters,
                                     const std::vector<uint8_t>& value,
                                     std::string& out_plaintext) const {
    return aes_128_cbc_decrypt(aes_key_, parameters, value, out_plaintext);
}

// SessionManager
std::shared_ptr<SecretSession> SessionManager::open_plain_session(std::string* out_path,
                                                                   SecretServiceImpl* service) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string path = "/org/freedesktop/secrets/session/s" + std::to_string(next_id_++);
    auto session = std::make_shared<PlainSecretSession>(path);
    if (service) session->set_service(service);
    sessions_[path] = session;
    if (out_path) *out_path = path;
    return session;
}

Result SessionManager::open_dh_session(const std::vector<uint8_t>& client_pub,
                                      std::vector<uint8_t>& out_server_pub,
                                      std::string& out_path,
                                      SecretServiceImpl* service) {
    DhOakley2Key server_key;
    if (server_key.public_key().empty()) {
        return Result::failure("Failed to generate server DH key");
    }

    AesKey aes_key;
    Result r = server_key.derive_aes_key(client_pub, aes_key);
    if (!r.ok) {
        return r;
    }

    out_server_pub = server_key.public_key();

    std::lock_guard<std::mutex> lock(mutex_);
    std::string path = "/org/freedesktop/secrets/session/s" + std::to_string(next_id_++);
    auto session = std::make_shared<DhSecretSession>(path, aes_key);
    if (service) session->set_service(service);
    sessions_[path] = session;
    out_path = path;
    return Result::success();
}

std::shared_ptr<SecretSession> SessionManager::find_session(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(path);
    if (it != sessions_.end()) {
        return it->second;
    }
    return nullptr;
}

bool SessionManager::close_session(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.erase(path) > 0;
}

void SessionManager::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    sessions_.clear();
}

}  // namespace brocred::secret_service
