// Secret Service Item representation.
#pragma once

#include "brocred/common.h"

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>

namespace brocred::secret_service {

class SecretServiceImpl;

class SecretItem {
public:
    SecretItem(std::string id,
               std::string path,
               std::string collection_id,
               std::string label,
               std::map<std::string, std::string> attributes,
               std::string secret,
               std::string content_type = "text/plain");

    ~SecretItem() = default;

    const std::string& id() const { return id_; }
    const std::string& path() const { return path_; }
    const std::string& collection_id() const { return collection_id_; }

    SecretServiceImpl* service() const { return service_; }
    void set_service(SecretServiceImpl* s) { service_ = s; }

    std::string label() const;
    void set_label(std::string label);

    std::map<std::string, std::string> attributes() const;
    void set_attributes(std::map<std::string, std::string> attributes);

    std::string secret() const;
    void set_secret(std::string secret);

    std::string content_type() const;
    void set_content_type(std::string content_type);

    uint64_t created() const { return created_; }
    uint64_t modified() const;

    bool is_locked() const;
    void set_locked(bool locked);

    // Checks if this item has all specified attributes with matching values
    bool matches_attributes(const std::map<std::string, std::string>& search_attrs) const;

private:
    const std::string id_;
    const std::string path_;
    const std::string collection_id_;
    SecretServiceImpl* service_ = nullptr;

    mutable std::mutex mutex_;
    std::string label_;
    std::map<std::string, std::string> attributes_;
    std::string secret_;
    std::string content_type_;
    const uint64_t created_;
    uint64_t modified_;
    bool locked_ = false;
};

}  // namespace brocred::secret_service
