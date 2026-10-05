// Public interface for Secret Service Provider (org.freedesktop.secrets).
#pragma once

#include "brocred/common.h"
#include "brocred/storage.h"

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace brocred {

struct SecretServiceOptions {
    // Underlying storage backend options (defaults to Auto / FileKeystore)
    StorageOptions storage_options;
    // Bus address or custom socket (empty = default session bus)
    std::string bus_address;
    // Whether to request the well-known bus name "org.freedesktop.secrets" (default true)
    bool request_well_known_name = true;
    // Default collection label
    std::string default_collection_label = "Default Keyring";
};

class SecretServiceProvider {
public:
    static std::unique_ptr<SecretServiceProvider> create(
        const SecretServiceOptions& options = {});

    static std::unique_ptr<SecretServiceProvider> create(
        std::unique_ptr<CredentialStore> store,
        const SecretServiceOptions& options = {});

    virtual ~SecretServiceProvider() = default;

    // Start background event loop thread
    virtual Result start() = 0;
    // Stop background event loop
    virtual void stop() = 0;
    // Check if background worker is active
    virtual bool is_running() const = 0;

    // Process a single D-Bus event iteration (useful for synchronous testing and event loop integration)
    virtual bool process_one(uint64_t timeout_usec = 0) = 0;

    // Access underlying credential store
    virtual CredentialStore* store() = 0;

    // List all collection object paths
    virtual std::vector<std::string> list_collection_paths() const = 0;

    // List item object paths in the given collection
    virtual std::vector<std::string> list_item_paths(const std::string& collection_path) const = 0;
};

}  // namespace brocred
