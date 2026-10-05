// Implementation of Secret Service item.
#include "linux/secret_service/secret_item.h"

namespace brocred::secret_service {

namespace {
uint64_t current_unix_time() {
    auto now = std::chrono::system_clock::now();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count());
}
}  // namespace

SecretItem::SecretItem(std::string id,
                       std::string path,
                       std::string collection_id,
                       std::string label,
                       std::map<std::string, std::string> attributes,
                       std::string secret,
                       std::string content_type)
    : id_(std::move(id)),
      path_(std::move(path)),
      collection_id_(std::move(collection_id)),
      label_(std::move(label)),
      attributes_(std::move(attributes)),
      secret_(std::move(secret)),
      content_type_(std::move(content_type)),
      created_(current_unix_time()),
      modified_(created_) {}

std::string SecretItem::label() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return label_;
}

void SecretItem::set_label(std::string label) {
    std::lock_guard<std::mutex> lock(mutex_);
    label_ = std::move(label);
    modified_ = current_unix_time();
}

std::map<std::string, std::string> SecretItem::attributes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return attributes_;
}

void SecretItem::set_attributes(std::map<std::string, std::string> attributes) {
    std::lock_guard<std::mutex> lock(mutex_);
    attributes_ = std::move(attributes);
    modified_ = current_unix_time();
}

std::string SecretItem::secret() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return secret_;
}

void SecretItem::set_secret(std::string secret) {
    std::lock_guard<std::mutex> lock(mutex_);
    secret_ = std::move(secret);
    modified_ = current_unix_time();
}

std::string SecretItem::content_type() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return content_type_;
}

void SecretItem::set_content_type(std::string content_type) {
    std::lock_guard<std::mutex> lock(mutex_);
    content_type_ = std::move(content_type);
    modified_ = current_unix_time();
}

uint64_t SecretItem::modified() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return modified_;
}

bool SecretItem::is_locked() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return locked_;
}

void SecretItem::set_locked(bool locked) {
    std::lock_guard<std::mutex> lock(mutex_);
    locked_ = locked;
}

bool SecretItem::matches_attributes(const std::map<std::string, std::string>& search_attrs) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [k, v] : search_attrs) {
        auto it = attributes_.find(k);
        if (it == attributes_.end() || it->second != v) {
            return false;
        }
    }
    return true;
}

}  // namespace brocred::secret_service
