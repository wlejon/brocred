#include "linux/linux_storage.h"
#include "common/memory_keystore.h"

namespace brocred {

std::unique_ptr<CredentialStore> CredentialStore::create() {
    return create(StorageOptions());
}

std::unique_ptr<CredentialStore> CredentialStore::create(const StorageOptions& options) {
    switch (options.backend) {
        case BackendType::Memory:
            return std::make_unique<MemoryKeystore>();
        case BackendType::FileKeystore:
            return std::make_unique<FileKeystore>(options.custom_file_path);
        case BackendType::System:
            return std::make_unique<LinuxSecretServiceStore>(options.custom_file_path, true);
        case BackendType::Auto:
        default:
            return std::make_unique<LinuxSecretServiceStore>(options.custom_file_path, false);
    }
}

LinuxSecretServiceStore::LinuxSecretServiceStore(std::string custom_file_path, bool force_system)
    : force_system_(force_system) {
    fallback_ = std::make_unique<FileKeystore>(std::move(custom_file_path));

    bus_ = linux_dbus::BusConnection::open(linux_dbus::BusType::User);
    if (!bus_ || !bus_->valid() || !bus_->has_owner("org.freedesktop.secrets")) {
        dbus_failed_ = true;
    }
}

bool LinuxSecretServiceStore::is_using_secret_service() const {
    return bus_ && bus_->valid() && !dbus_failed_;
}

std::string LinuxSecretServiceStore::backend_name() const {
    if (is_using_secret_service()) {
        return "SecretService";
    }
    return "FileKeystore";
}

bool LinuxSecretServiceStore::ensure_session(std::string* error) {
    if (!is_using_secret_service()) {
        if (error) {
#if defined(BROCRED_HAVE_SDBUS)
            *error = bus_ && bus_->valid()
                ? "no org.freedesktop.secrets service on the session bus"
                : "cannot connect to the D-Bus session bus";
#else
            *error = linux_dbus::kNoSdBus;
#endif
        }
        return false;
    }
    if (!session_path_.empty()) return true;

    if (!bus_->secret_service_open_session(session_path_, error)) {
        if (!force_system_) {
            dbus_failed_ = true;
        }
        return false;
    }
    return true;
}

Result LinuxSecretServiceStore::store_secret(const std::string& service, const std::string& account,
                                            const std::string& secret) {
    return store_secret(service, account, secret, {});
}

Result LinuxSecretServiceStore::store_secret(const std::string& service, const std::string& account,
                                            const std::string& secret,
                                            const std::map<std::string, std::string>& attributes) {
    if (service.empty()) {
        return Result::failure("Service name cannot be empty");
    }

    std::string err;
    if (ensure_session(&err)) {
        std::map<std::string, std::string> full_attrs = attributes;
        full_attrs["service"] = service;
        if (!account.empty()) {
            full_attrs["account"] = account;
        }

        std::string label = service;
        if (!account.empty()) {
            label += " (" + account + ")";
        }

        std::string item_path;
        if (bus_->secret_service_create_item("", session_path_, label, full_attrs, secret,
                                             true, item_path, &err)) {
            CredentialChangedEvent ev;
            ev.change = CredentialChangedEvent::ChangeType::Stored;
            ev.service = service;
            ev.account = account;
            events_.push(std::move(ev));
            return Result::success();
        }

        if (force_system_) {
            return Result::failure("Secret Service CreateItem failed: " + err);
        }
        dbus_failed_ = true;
    }

    if (force_system_) {
        return Result::failure("Secret Service daemon unavailable: " + err);
    }

    Result res = fallback_->store_secret(service, account, secret, attributes);
    if (res) {
        CredentialChangedEvent ev;
        ev.change = CredentialChangedEvent::ChangeType::Stored;
        ev.service = service;
        ev.account = account;
        events_.push(std::move(ev));
    }
    return res;
}

std::optional<std::string> LinuxSecretServiceStore::read_secret(const std::string& service,
                                                               const std::string& account) {
    auto cred = read_credential(service, account);
    if (!cred) return std::nullopt;
    return cred->secret;
}

std::optional<Credential> LinuxSecretServiceStore::read_credential(const std::string& service,
                                                                  const std::string& account) {
    if (service.empty()) return std::nullopt;

    std::string err;
    if (ensure_session(&err)) {
        std::map<std::string, std::string> query_attrs;
        query_attrs["service"] = service;
        if (!account.empty()) {
            query_attrs["account"] = account;
        }

        std::vector<std::string> unlocked, locked;
        if (bus_->secret_service_search_items(query_attrs, unlocked, locked, &err)) {
            if (unlocked.empty() && !locked.empty()) {
                bus_->secret_service_unlock(locked, unlocked);
            }

            for (const auto& item_path : unlocked) {
                std::string secret_val;
                if (bus_->secret_service_get_secret(item_path, session_path_, secret_val, &err)) {
                    Credential cred;
                    cred.service = service;
                    cred.account = account;
                    cred.secret = std::move(secret_val);

                    std::map<std::string, std::string> item_attrs;
                    if (bus_->secret_service_get_item_attributes(item_path, item_attrs, &err)) {
                        for (auto& [k, v] : item_attrs) {
                            if (k == "account" && cred.account.empty()) {
                                cred.account = v;
                            } else if (k != "service" && k != "account") {
                                cred.attributes[k] = std::move(v);
                            }
                        }
                    }
                    return cred;
                }
            }
        }
        if (force_system_) {
            return std::nullopt;
        }
        dbus_failed_ = true;
    }

    if (force_system_) {
        return std::nullopt;
    }
    return fallback_->read_credential(service, account);
}

Result LinuxSecretServiceStore::delete_secret(const std::string& service, const std::string& account) {
    if (service.empty()) {
        return Result::failure("Service name cannot be empty");
    }

    std::string err;
    if (ensure_session(&err)) {
        std::map<std::string, std::string> query_attrs;
        query_attrs["service"] = service;
        if (!account.empty()) {
            query_attrs["account"] = account;
        }

        std::vector<std::string> unlocked, locked;
        if (bus_->secret_service_search_items(query_attrs, unlocked, locked, &err)) {
            bool deleted = false;
            std::vector<std::string> all_items = unlocked;
            all_items.insert(all_items.end(), locked.begin(), locked.end());

            for (const auto& item_path : all_items) {
                if (bus_->secret_service_delete_item(item_path, &err)) {
                    deleted = true;
                }
            }

            if (deleted) {
                CredentialChangedEvent ev;
                ev.change = CredentialChangedEvent::ChangeType::Deleted;
                ev.service = service;
                ev.account = account;
                events_.push(std::move(ev));
                return Result::success();
            }
            if (all_items.empty()) {
                return Result::failure("Credential not found");
            }
        }
        if (force_system_) {
            return Result::failure("Delete failed in Secret Service: " + err);
        }
        dbus_failed_ = true;
    }

    if (force_system_) {
        return Result::failure("Secret Service daemon unavailable: " + err);
    }

    Result res = fallback_->delete_secret(service, account);
    if (res) {
        CredentialChangedEvent ev;
        ev.change = CredentialChangedEvent::ChangeType::Deleted;
        ev.service = service;
        ev.account = account;
        events_.push(std::move(ev));
    }
    return res;
}

std::vector<CredentialMetadata> LinuxSecretServiceStore::list_credentials() {
    return list_credentials("");
}

std::vector<CredentialMetadata> LinuxSecretServiceStore::list_credentials(const std::string& service) {
    std::string err;
    if (ensure_session(&err)) {
        std::map<std::string, std::string> query_attrs;
        if (!service.empty()) {
            query_attrs["service"] = service;
        }

        std::vector<std::string> unlocked, locked;
        if (bus_->secret_service_search_items(query_attrs, unlocked, locked, &err)) {
            std::vector<CredentialMetadata> out;
            std::vector<std::string> all_items = unlocked;
            all_items.insert(all_items.end(), locked.begin(), locked.end());

            for (const auto& item_path : all_items) {
                std::map<std::string, std::string> item_attrs;
                if (bus_->secret_service_get_item_attributes(item_path, item_attrs, &err)) {
                    CredentialMetadata meta;
                    auto svc_it = item_attrs.find("service");
                    if (svc_it != item_attrs.end()) {
                        meta.service = svc_it->second;
                    }
                    auto acc_it = item_attrs.find("account");
                    if (acc_it != item_attrs.end()) {
                        meta.account = acc_it->second;
                    }
                    for (const auto& [k, v] : item_attrs) {
                        if (k != "service" && k != "account") {
                            meta.attributes[k] = v;
                        }
                    }
                    meta.last_modified = std::chrono::system_clock::now();
                    out.push_back(std::move(meta));
                }
            }
            return out;
        }
        if (force_system_) {
            return {};
        }
        dbus_failed_ = true;
    }

    if (force_system_) {
        return {};
    }
    return fallback_->list_credentials(service);
}

}  // namespace brocred
