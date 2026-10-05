#include "common/memory_keystore.h"

namespace brocred {

Result MemoryKeystore::store_secret(const std::string& service, const std::string& account,
                                    const std::string& secret) {
    return store_secret(service, account, secret, {});
}

Result MemoryKeystore::store_secret(const std::string& service, const std::string& account,
                                    const std::string& secret,
                                    const std::map<std::string, std::string>& attributes) {
    if (service.empty()) {
        return Result::failure("Service name cannot be empty");
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto key = std::make_pair(service, account);
        Credential cred;
        cred.service = service;
        cred.account = account;
        cred.secret = secret;
        cred.attributes = attributes;
        items_[key] = std::move(cred);
        timestamps_[key] = std::chrono::system_clock::now();
    }
    CredentialChangedEvent ev;
    ev.change = CredentialChangedEvent::ChangeType::Stored;
    ev.service = service;
    ev.account = account;
    events_.push(std::move(ev));
    return Result::success();
}

std::optional<std::string> MemoryKeystore::read_secret(const std::string& service,
                                                       const std::string& account) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = items_.find(std::make_pair(service, account));
    if (it == items_.end()) {
        return std::nullopt;
    }
    return it->second.secret;
}

std::optional<Credential> MemoryKeystore::read_credential(const std::string& service,
                                                          const std::string& account) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = items_.find(std::make_pair(service, account));
    if (it == items_.end()) {
        return std::nullopt;
    }
    return it->second;
}

Result MemoryKeystore::delete_secret(const std::string& service, const std::string& account) {
    bool found = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto key = std::make_pair(service, account);
        if (items_.erase(key) > 0) {
            timestamps_.erase(key);
            found = true;
        }
    }
    if (!found) {
        return Result::failure("Credential not found");
    }
    CredentialChangedEvent ev;
    ev.change = CredentialChangedEvent::ChangeType::Deleted;
    ev.service = service;
    ev.account = account;
    events_.push(std::move(ev));
    return Result::success();
}

std::vector<CredentialMetadata> MemoryKeystore::list_credentials() {
    return list_credentials("");
}

std::vector<CredentialMetadata> MemoryKeystore::list_credentials(const std::string& service) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<CredentialMetadata> list;
    for (const auto& [key, cred] : items_) {
        if (service.empty() || cred.service == service) {
            CredentialMetadata meta;
            meta.service = cred.service;
            meta.account = cred.account;
            meta.attributes = cred.attributes;
            auto ts_it = timestamps_.find(key);
            if (ts_it != timestamps_.end()) {
                meta.last_modified = ts_it->second;
            }
            list.push_back(std::move(meta));
        }
    }
    return list;
}

}  // namespace brocred
