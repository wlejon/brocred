// Credential storage API: native OS vault with file/memory keystore fallback.
#pragma once

#include "brocred/common.h"
#include "brocred/credential.h"
#include "brocred/events.h"

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace brocred {

enum class BackendType {
    Auto,         // Uses native OS store if available, falls back to FileKeystore
    System,       // Enforces native OS store (WinCred / Keychain / Secret Service)
    FileKeystore, // Private encrypted or protected JSON keystore on disk
    Memory,       // In-memory keystore (useful for ephemeral sessions and testing)
};

struct StorageOptions {
    BackendType backend = BackendType::Auto;
    std::string custom_file_path; // Used when backend is FileKeystore or fallback
};

class CredentialStore {
public:
    static std::unique_ptr<CredentialStore> create();
    static std::unique_ptr<CredentialStore> create(const StorageOptions& options);

    virtual ~CredentialStore() = default;

    virtual Result store_secret(const std::string& service, const std::string& account,
                                const std::string& secret) = 0;
    virtual Result store_secret(const std::string& service, const std::string& account,
                                const std::string& secret,
                                const std::map<std::string, std::string>& attributes) = 0;

    virtual std::optional<std::string> read_secret(const std::string& service,
                                                   const std::string& account) = 0;
    virtual std::optional<Credential> read_credential(const std::string& service,
                                                      const std::string& account) = 0;

    virtual Result delete_secret(const std::string& service, const std::string& account) = 0;

    virtual std::vector<CredentialMetadata> list_credentials() = 0;
    virtual std::vector<CredentialMetadata> list_credentials(const std::string& service) = 0;

    virtual EventQueue& events() = 0;
    virtual std::string backend_name() const = 0;
};

// Global convenience functions using the default system store:
Result store_secret(const std::string& service, const std::string& account,
                    const std::string& secret);
Result store_secret(const std::string& service, const std::string& account,
                    const std::string& secret,
                    const std::map<std::string, std::string>& attributes);

std::optional<std::string> read_secret(const std::string& service,
                                       const std::string& account);

Result delete_secret(const std::string& service, const std::string& account);

std::vector<CredentialMetadata> list_credentials();
std::vector<CredentialMetadata> list_credentials(const std::string& service);

}  // namespace brocred
