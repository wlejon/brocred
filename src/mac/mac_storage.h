// macOS Apple Keychain Services storage implementation.
#pragma once

#include "brocred/storage.h"

namespace brocred {

class MacKeychainStore : public CredentialStore {
public:
    MacKeychainStore() = default;
    ~MacKeychainStore() override = default;

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
    std::string backend_name() const override { return "AppleKeychain"; }

private:
    EventQueue events_;
};

}  // namespace brocred
