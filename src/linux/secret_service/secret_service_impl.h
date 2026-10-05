// Internal implementation of Secret Service D-Bus provider.
#pragma once

#include "brocred/secret_service.h"
#include "linux/secret_service/secret_collection.h"
#include "linux/secret_service/secret_session.h"

#include <systemd/sd-bus.h>

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace brocred::secret_service {

class SecretServiceImpl : public SecretServiceProvider {
public:
    explicit SecretServiceImpl(SecretServiceOptions options,
                               std::unique_ptr<CredentialStore> store = nullptr);
    ~SecretServiceImpl() override;

    Result start() override;
    void stop() override;
    bool is_running() const override { return running_.load(); }

    bool process_one(uint64_t timeout_usec = 0) override;

    CredentialStore* store() override { return store_.get(); }

    std::vector<std::string> list_collection_paths() const override;
    std::vector<std::string> list_item_paths(const std::string& collection_path) const override;

    // Internal accessors
    SessionManager& session_manager() { return session_manager_; }
    std::shared_ptr<SecretCollection> find_collection(const std::string& path_or_alias) const;
    std::shared_ptr<SecretItem> find_item(const std::string& path) const;
    std::shared_ptr<SecretCollection> create_collection(const std::string& id,
                                                        const std::string& label,
                                                        const std::string& alias);
    bool delete_collection(const std::string& path);

    sd_bus* bus() const { return bus_; }

    // D-Bus handlers for org.freedesktop.Secret.Service
    int handle_open_session(sd_bus_message* m, sd_bus_error* ret_error);
    int handle_create_collection(sd_bus_message* m, sd_bus_error* ret_error);
    int handle_search_items(sd_bus_message* m, sd_bus_error* ret_error);
    int handle_unlock(sd_bus_message* m, sd_bus_error* ret_error);
    int handle_lock(sd_bus_message* m, sd_bus_error* ret_error);
    int handle_get_secrets(sd_bus_message* m, sd_bus_error* ret_error);
    int handle_read_alias(sd_bus_message* m, sd_bus_error* ret_error);
    int handle_set_alias(sd_bus_message* m, sd_bus_error* ret_error);

    // D-Bus handlers for org.freedesktop.Secret.Collection
    int handle_collection_create_item(sd_bus_message* m, void* userdata, sd_bus_error* ret_error);
    int handle_collection_delete(sd_bus_message* m, void* userdata, sd_bus_error* ret_error);
    int handle_collection_search_items(sd_bus_message* m, void* userdata, sd_bus_error* ret_error);

    // D-Bus handlers for org.freedesktop.Secret.Item
    int handle_item_get_secret(sd_bus_message* m, void* userdata, sd_bus_error* ret_error);
    int handle_item_set_secret(sd_bus_message* m, void* userdata, sd_bus_error* ret_error);
    int handle_item_delete(sd_bus_message* m, void* userdata, sd_bus_error* ret_error);

    // D-Bus handler for org.freedesktop.Secret.Session
    int handle_session_close(sd_bus_message* m, void* userdata, sd_bus_error* ret_error);

private:
    Result init_bus();
    void run_worker();

    SecretServiceOptions options_;
    std::shared_ptr<CredentialStore> store_;
    SessionManager session_manager_;

    mutable std::mutex mutex_;
    std::map<std::string, std::shared_ptr<SecretCollection>> collections_;
    std::map<std::string, std::string> aliases_;
    uint64_t next_collection_id_ = 1;

    sd_bus* bus_ = nullptr;
    std::vector<sd_bus_slot*> slots_;

    std::atomic<bool> running_{false};
    std::thread worker_thread_;
};

}  // namespace brocred::secret_service
