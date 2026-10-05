// Implementation of Secret Service collection.
#include "linux/secret_service/secret_collection.h"

namespace brocred::secret_service {

namespace {
uint64_t current_unix_time() {
    auto now = std::chrono::system_clock::now();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count());
}

std::string extract_service(const std::map<std::string, std::string>& attrs, const std::string& label) {
    auto it = attrs.find("service");
    if (it != attrs.end() && !it->second.empty()) return it->second;
    if (!label.empty()) return label;
    return "default_service";
}

std::string extract_account(const std::map<std::string, std::string>& attrs) {
    auto it = attrs.find("account");
    if (it != attrs.end() && !it->second.empty()) return it->second;
    auto it2 = attrs.find("username");
    if (it2 != attrs.end() && !it2->second.empty()) return it2->second;
    return "default_account";
}
}  // namespace

SecretCollection::SecretCollection(std::string id,
                                   std::string path,
                                   std::string label,
                                   std::shared_ptr<CredentialStore> backing_store)
    : id_(std::move(id)),
      path_(std::move(path)),
      store_(std::move(backing_store)),
      label_(std::move(label)),
      created_(current_unix_time()),
      modified_(created_) {
    load_from_store();
}

std::string SecretCollection::label() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return label_;
}

void SecretCollection::set_label(std::string label) {
    std::lock_guard<std::mutex> lock(mutex_);
    label_ = std::move(label);
    modified_ = current_unix_time();
}

bool SecretCollection::is_locked() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return locked_;
}

void SecretCollection::set_locked(bool locked) {
    std::lock_guard<std::mutex> lock(mutex_);
    locked_ = locked;
}

uint64_t SecretCollection::modified() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return modified_;
}

std::shared_ptr<SecretItem> SecretCollection::create_or_replace_item(
    const std::string& label,
    const std::map<std::string, std::string>& attributes,
    const std::string& secret,
    const std::string& content_type,
    bool replace) {
    std::lock_guard<std::mutex> lock(mutex_);

    // If replace is true, look for an item with matching attributes
    if (replace) {
        for (auto& [_, item] : items_by_id_) {
            if (item->attributes() == attributes) {
                item->set_label(label);
                item->set_secret(secret);
                item->set_content_type(content_type);
                modified_ = current_unix_time();
                persist_item(item);
                return item;
            }
        }
    }

    std::string item_id = "i" + std::to_string(next_item_id_++);
    std::string item_path = path_ + "/" + item_id;

    auto item = std::make_shared<SecretItem>(item_id,
                                            item_path,
                                            id_,
                                            label,
                                            attributes,
                                            secret,
                                            content_type);
    item->set_service(service_);
    items_by_id_[item_id] = item;
    items_by_path_[item_path] = item;
    modified_ = current_unix_time();

    persist_item(item);
    return item;
}

std::shared_ptr<SecretItem> SecretCollection::find_item_by_path(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = items_by_path_.find(path);
    if (it != items_by_path_.end()) {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<SecretItem> SecretCollection::find_item_by_id(const std::string& id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = items_by_id_.find(id);
    if (it != items_by_id_.end()) {
        return it->second;
    }
    return nullptr;
}

bool SecretCollection::delete_item(const std::string& item_path_or_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::shared_ptr<SecretItem> item;

    auto it_path = items_by_path_.find(item_path_or_id);
    if (it_path != items_by_path_.end()) {
        item = it_path->second;
    } else {
        auto it_id = items_by_id_.find(item_path_or_id);
        if (it_id != items_by_id_.end()) {
            item = it_id->second;
        }
    }

    if (!item) {
        return false;
    }

    items_by_id_.erase(item->id());
    items_by_path_.erase(item->path());
    modified_ = current_unix_time();

    unpersist_item(item);
    return true;
}

std::vector<std::shared_ptr<SecretItem>> SecretCollection::search_items(
    const std::map<std::string, std::string>& search_attrs) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<SecretItem>> result;
    for (const auto& [_, item] : items_by_id_) {
        if (item->matches_attributes(search_attrs)) {
            result.push_back(item);
        }
    }
    return result;
}

std::vector<std::string> SecretCollection::item_paths() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> paths;
    paths.reserve(items_by_path_.size());
    for (const auto& [p, _] : items_by_path_) {
        paths.push_back(p);
    }
    return paths;
}

size_t SecretCollection::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return items_by_id_.size();
}

void SecretCollection::persist_item(const std::shared_ptr<SecretItem>& item) {
    if (!store_) return;
    auto attrs = item->attributes();
    std::string svc = extract_service(attrs, item->label());
    std::string acc = extract_account(attrs);
    store_->store_secret(svc, acc, item->secret(), attrs);
}

void SecretCollection::unpersist_item(const std::shared_ptr<SecretItem>& item) {
    if (!store_) return;
    auto attrs = item->attributes();
    std::string svc = extract_service(attrs, item->label());
    std::string acc = extract_account(attrs);
    store_->delete_secret(svc, acc);
}

void SecretCollection::load_from_store() {
    if (!store_) return;
    std::lock_guard<std::mutex> lock(mutex_);

    auto creds = store_->list_credentials();
    for (const auto& meta : creds) {
        auto full_cred = store_->read_credential(meta.service, meta.account);
        if (!full_cred) continue;

        std::string item_id = "i" + std::to_string(next_item_id_++);
        std::string item_path = path_ + "/" + item_id;

        std::map<std::string, std::string> attrs = full_cred->attributes;
        if (attrs.find("service") == attrs.end()) attrs["service"] = full_cred->service;
        if (attrs.find("account") == attrs.end() && !full_cred->account.empty()) {
            attrs["account"] = full_cred->account;
        }

        std::string label = full_cred->service;
        if (!full_cred->account.empty()) {
            label += " (" + full_cred->account + ")";
        }

        auto item = std::make_shared<SecretItem>(item_id,
                                                item_path,
                                                id_,
                                                label,
                                                attrs,
                                                full_cred->secret);
        item->set_service(service_);
        items_by_id_[item_id] = item;
        items_by_path_[item_path] = item;
    }
}

}  // namespace brocred::secret_service
