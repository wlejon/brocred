// Secret Service Collection management.
#pragma once

#include "brocred/common.h"
#include "brocred/storage.h"
#include "linux/secret_service/secret_item.h"

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace brocred::secret_service {

class SecretServiceImpl;

class SecretCollection {
public:
    SecretCollection(std::string id,
                     std::string path,
                     std::string label,
                     std::shared_ptr<CredentialStore> backing_store = nullptr);

    ~SecretCollection() = default;

    const std::string& id() const { return id_; }
    const std::string& path() const { return path_; }

    SecretServiceImpl* service() const { return service_; }
    void set_service(SecretServiceImpl* s) { service_ = s; }

    std::string label() const;
    void set_label(std::string label);

    bool is_locked() const;
    void set_locked(bool locked);

    uint64_t created() const { return created_; }
    uint64_t modified() const;

    // Create or replace an item. If replace is true and an item with identical attributes exists, updates it.
    std::shared_ptr<SecretItem> create_or_replace_item(const std::string& label,
                                                      const std::map<std::string, std::string>& attributes,
                                                      const std::string& secret,
                                                      const std::string& content_type,
                                                      bool replace);

    std::shared_ptr<SecretItem> find_item_by_path(const std::string& path) const;
    std::shared_ptr<SecretItem> find_item_by_id(const std::string& id) const;

    bool delete_item(const std::string& item_path_or_id);

    std::vector<std::shared_ptr<SecretItem>> search_items(const std::map<std::string, std::string>& search_attrs) const;

    std::vector<std::string> item_paths() const;
    size_t size() const;

    // Initial load from backing CredentialStore
    void load_from_store();

private:
    void persist_item(const std::shared_ptr<SecretItem>& item);
    void unpersist_item(const std::shared_ptr<SecretItem>& item);

    const std::string id_;
    const std::string path_;
    std::shared_ptr<CredentialStore> store_;
    SecretServiceImpl* service_ = nullptr;

    mutable std::mutex mutex_;
    std::string label_;
    bool locked_ = false;
    const uint64_t created_;
    uint64_t modified_;
    uint64_t next_item_id_ = 1;

    // Map by item ID
    std::map<std::string, std::shared_ptr<SecretItem>> items_by_id_;
    // Map by object path
    std::map<std::string, std::shared_ptr<SecretItem>> items_by_path_;
};

}  // namespace brocred::secret_service
