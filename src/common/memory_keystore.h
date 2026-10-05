// In-memory credential store.
#pragma once

#include "brocred/storage.h"

#include <map>
#include <mutex>
#include <string>
#include <utility>

namespace brocred {

class MemoryKeystore : public CredentialStore {
public:
    MemoryKeystore() = default;
    ~MemoryKeystore() override = default;

    Result store_secret(const std::string& service, const std::string& account,
                        const std::string& secret) override;
    Result store_secret(const std::string& service, const std::string& account,
                        const std::string& secret,
                        const std::map<std::string, std::string>& attributes) override;

    std::optional<std::string> read_secret(const std::string& service,
                                           const std::string& account) override;
    std::optional<Credential> read_credential(const std::string& service,
                                              const std::string& account) override;

    Result delete_secret(const std::string& service, const std::string& account) override;

    std::vector<CredentialMetadata> list_credentials() override;
    std::vector<CredentialMetadata> list_credentials(const std::string& service) override;

    EventQueue& events() override { return events_; }
    std::string backend_name() const override { return "Memory"; }

protected:
    mutable std::mutex mutex_;
    std::map<std::pair<std::string, std::string>, Credential> items_;
    std::map<std::pair<std::string, std::string>, std::chrono::system_clock::time_point> timestamps_;
    EventQueue events_;
};

}  // namespace brocred
