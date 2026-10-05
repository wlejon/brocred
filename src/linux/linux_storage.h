// Linux Secret Service storage with fallback to file keystore.
#pragma once

#include "brocred/storage.h"
#include "common/file_keystore.h"
#if defined(BROCRED_HAVE_SDBUS)
#include "linux/dbus/dbus_bus.h"
#else
#include "linux/dbus/dbus_unavailable.h"
#endif

#include <memory>
#include <string>

namespace brocred {

class LinuxSecretServiceStore : public CredentialStore {
public:
    explicit LinuxSecretServiceStore(std::string custom_file_path = "",
                                     bool force_system = false);
    ~LinuxSecretServiceStore() override = default;

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
    std::string backend_name() const override;

    bool is_using_secret_service() const;

private:
    bool ensure_session(std::string* error = nullptr);

    std::unique_ptr<linux_dbus::BusConnection> bus_;
    std::string session_path_;
    std::unique_ptr<FileKeystore> fallback_;
    EventQueue events_;
    bool force_system_ = false;
    bool dbus_failed_ = false;
};

}  // namespace brocred
