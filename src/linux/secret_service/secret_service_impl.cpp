// Implementation of Secret Service Provider D-Bus export and life cycle.
#include "linux/secret_service/secret_service_impl.h"

#include <cstring>
#include <unistd.h>

namespace brocred::secret_service {

namespace {

// Object finders for fallback vtables
int find_collection_obj(sd_bus* /*bus*/, const char* path, const char* interface,
                        void* userdata, void** ret_found, sd_bus_error* /*ret_error*/) {
    if (std::strcmp(interface, "org.freedesktop.Secret.Collection") != 0 &&
        std::strcmp(interface, "org.freedesktop.DBus.Properties") != 0) {
        return 0;
    }
    auto* srv = static_cast<SecretServiceImpl*>(userdata);
    auto coll = srv->find_collection(path);
    if (!coll) return 0;
    *ret_found = coll.get();
    return 1;
}

int find_item_obj(sd_bus* /*bus*/, const char* path, const char* interface,
                  void* userdata, void** ret_found, sd_bus_error* /*ret_error*/) {
    if (std::strcmp(interface, "org.freedesktop.Secret.Item") != 0 &&
        std::strcmp(interface, "org.freedesktop.DBus.Properties") != 0) {
        return 0;
    }
    auto* srv = static_cast<SecretServiceImpl*>(userdata);
    auto item = srv->find_item(path);
    if (!item) return 0;
    *ret_found = item.get();
    return 1;
}

int find_session_obj(sd_bus* /*bus*/, const char* path, const char* interface,
                     void* userdata, void** ret_found, sd_bus_error* /*ret_error*/) {
    if (std::strcmp(interface, "org.freedesktop.Secret.Session") != 0) {
        return 0;
    }
    auto* srv = static_cast<SecretServiceImpl*>(userdata);
    auto sess = srv->session_manager().find_session(path);
    if (!sess) return 0;
    *ret_found = sess.get();
    return 1;
}

// Property getters
int get_service_collections(sd_bus* /*bus*/, const char* /*path*/, const char* /*interface*/,
                            const char* /*property*/, sd_bus_message* reply,
                            void* userdata, sd_bus_error* /*ret_error*/) {
    auto* srv = static_cast<SecretServiceImpl*>(userdata);
    auto paths = srv->list_collection_paths();
    int r = sd_bus_message_open_container(reply, 'a', "o");
    if (r < 0) return r;
    for (const auto& p : paths) {
        sd_bus_message_append(reply, "o", p.c_str());
    }
    return sd_bus_message_close_container(reply);
}

int get_collection_items(sd_bus* /*bus*/, const char* /*path*/, const char* /*interface*/,
                         const char* /*property*/, sd_bus_message* reply,
                         void* userdata, sd_bus_error* /*ret_error*/) {
    auto* coll = static_cast<SecretCollection*>(userdata);
    auto paths = coll->item_paths();
    int r = sd_bus_message_open_container(reply, 'a', "o");
    if (r < 0) return r;
    for (const auto& p : paths) {
        sd_bus_message_append(reply, "o", p.c_str());
    }
    return sd_bus_message_close_container(reply);
}

int get_collection_label(sd_bus* /*bus*/, const char* /*path*/, const char* /*interface*/,
                         const char* /*property*/, sd_bus_message* reply,
                         void* userdata, sd_bus_error* /*ret_error*/) {
    auto* coll = static_cast<SecretCollection*>(userdata);
    return sd_bus_message_append(reply, "s", coll->label().c_str());
}

int get_collection_locked(sd_bus* /*bus*/, const char* /*path*/, const char* /*interface*/,
                          const char* /*property*/, sd_bus_message* reply,
                          void* userdata, sd_bus_error* /*ret_error*/) {
    auto* coll = static_cast<SecretCollection*>(userdata);
    return sd_bus_message_append(reply, "b", coll->is_locked() ? 1 : 0);
}

int get_collection_created(sd_bus* /*bus*/, const char* /*path*/, const char* /*interface*/,
                           const char* /*property*/, sd_bus_message* reply,
                           void* userdata, sd_bus_error* /*ret_error*/) {
    auto* coll = static_cast<SecretCollection*>(userdata);
    return sd_bus_message_append(reply, "t", coll->created());
}

int get_collection_modified(sd_bus* /*bus*/, const char* /*path*/, const char* /*interface*/,
                            const char* /*property*/, sd_bus_message* reply,
                            void* userdata, sd_bus_error* /*ret_error*/) {
    auto* coll = static_cast<SecretCollection*>(userdata);
    return sd_bus_message_append(reply, "t", coll->modified());
}

int get_item_locked(sd_bus* /*bus*/, const char* /*path*/, const char* /*interface*/,
                    const char* /*property*/, sd_bus_message* reply,
                    void* userdata, sd_bus_error* /*ret_error*/) {
    auto* item = static_cast<SecretItem*>(userdata);
    return sd_bus_message_append(reply, "b", item->is_locked() ? 1 : 0);
}

int get_item_attributes(sd_bus* /*bus*/, const char* /*path*/, const char* /*interface*/,
                        const char* /*property*/, sd_bus_message* reply,
                        void* userdata, sd_bus_error* /*ret_error*/) {
    auto* item = static_cast<SecretItem*>(userdata);
    auto attrs = item->attributes();
    int r = sd_bus_message_open_container(reply, 'a', "{ss}");
    if (r < 0) return r;
    for (const auto& [k, v] : attrs) {
        sd_bus_message_append(reply, "{ss}", k.c_str(), v.c_str());
    }
    return sd_bus_message_close_container(reply);
}

int get_item_label(sd_bus* /*bus*/, const char* /*path*/, const char* /*interface*/,
                   const char* /*property*/, sd_bus_message* reply,
                   void* userdata, sd_bus_error* /*ret_error*/) {
    auto* item = static_cast<SecretItem*>(userdata);
    return sd_bus_message_append(reply, "s", item->label().c_str());
}

int get_item_created(sd_bus* /*bus*/, const char* /*path*/, const char* /*interface*/,
                     const char* /*property*/, sd_bus_message* reply,
                     void* userdata, sd_bus_error* /*ret_error*/) {
    auto* item = static_cast<SecretItem*>(userdata);
    return sd_bus_message_append(reply, "t", item->created());
}

int get_item_modified(sd_bus* /*bus*/, const char* /*path*/, const char* /*interface*/,
                      const char* /*property*/, sd_bus_message* reply,
                      void* userdata, sd_bus_error* /*ret_error*/) {
    auto* item = static_cast<SecretItem*>(userdata);
    return sd_bus_message_append(reply, "t", item->modified());
}

// Method trampolines
int dbus_srv_open_session(sd_bus_message* m, void* ud, sd_bus_error* err) {
    return static_cast<SecretServiceImpl*>(ud)->handle_open_session(m, err);
}
int dbus_srv_create_collection(sd_bus_message* m, void* ud, sd_bus_error* err) {
    return static_cast<SecretServiceImpl*>(ud)->handle_create_collection(m, err);
}
int dbus_srv_search_items(sd_bus_message* m, void* ud, sd_bus_error* err) {
    return static_cast<SecretServiceImpl*>(ud)->handle_search_items(m, err);
}
int dbus_srv_unlock(sd_bus_message* m, void* ud, sd_bus_error* err) {
    return static_cast<SecretServiceImpl*>(ud)->handle_unlock(m, err);
}
int dbus_srv_lock(sd_bus_message* m, void* ud, sd_bus_error* err) {
    return static_cast<SecretServiceImpl*>(ud)->handle_lock(m, err);
}
int dbus_srv_get_secrets(sd_bus_message* m, void* ud, sd_bus_error* err) {
    return static_cast<SecretServiceImpl*>(ud)->handle_get_secrets(m, err);
}
int dbus_srv_read_alias(sd_bus_message* m, void* ud, sd_bus_error* err) {
    return static_cast<SecretServiceImpl*>(ud)->handle_read_alias(m, err);
}
int dbus_srv_set_alias(sd_bus_message* m, void* ud, sd_bus_error* err) {
    return static_cast<SecretServiceImpl*>(ud)->handle_set_alias(m, err);
}

int dbus_coll_create_item(sd_bus_message* m, void* ud, sd_bus_error* err) {
    auto* coll = static_cast<SecretCollection*>(ud);
    return coll->service()->handle_collection_create_item(m, coll, err);
}
int dbus_coll_delete(sd_bus_message* m, void* ud, sd_bus_error* err) {
    auto* coll = static_cast<SecretCollection*>(ud);
    return coll->service()->handle_collection_delete(m, coll, err);
}
int dbus_coll_search_items(sd_bus_message* m, void* ud, sd_bus_error* err) {
    auto* coll = static_cast<SecretCollection*>(ud);
    return coll->service()->handle_collection_search_items(m, coll, err);
}

int dbus_item_get_secret(sd_bus_message* m, void* ud, sd_bus_error* err) {
    auto* item = static_cast<SecretItem*>(ud);
    return item->service()->handle_item_get_secret(m, item, err);
}
int dbus_item_set_secret(sd_bus_message* m, void* ud, sd_bus_error* err) {
    auto* item = static_cast<SecretItem*>(ud);
    return item->service()->handle_item_set_secret(m, item, err);
}
int dbus_item_delete(sd_bus_message* m, void* ud, sd_bus_error* err) {
    auto* item = static_cast<SecretItem*>(ud);
    return item->service()->handle_item_delete(m, item, err);
}

int dbus_sess_close(sd_bus_message* m, void* ud, sd_bus_error* err) {
    auto* sess = static_cast<SecretSession*>(ud);
    return sess->service()->handle_session_close(m, sess, err);
}

// Vtables
const sd_bus_vtable kSecretServiceVtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("OpenSession", "sv", "vo", dbus_srv_open_session, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("CreateCollection", "a{sv}s", "oo", dbus_srv_create_collection, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("SearchItems", "a{ss}", "aoao", dbus_srv_search_items, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("Unlock", "ao", "aoo", dbus_srv_unlock, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("Lock", "ao", "aoo", dbus_srv_lock, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("GetSecrets", "aoo", "a{o(oayays)}", dbus_srv_get_secrets, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("ReadAlias", "s", "o", dbus_srv_read_alias, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("SetAlias", "so", "", dbus_srv_set_alias, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_PROPERTY("Collections", "ao", get_service_collections, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_VTABLE_END
};

const sd_bus_vtable kCollectionVtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("CreateItem", "a{sv}(oayays)b", "oo", dbus_coll_create_item, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("Delete", "", "o", dbus_coll_delete, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("SearchItems", "a{ss}", "ao", dbus_coll_search_items, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_PROPERTY("Items", "ao", get_collection_items, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("Label", "s", get_collection_label, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("Locked", "b", get_collection_locked, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("Created", "t", get_collection_created, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Modified", "t", get_collection_modified, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_VTABLE_END
};

const sd_bus_vtable kItemVtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("GetSecret", "o", "(oayays)", dbus_item_get_secret, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("SetSecret", "(oayays)", "", dbus_item_set_secret, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("Delete", "", "o", dbus_item_delete, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_PROPERTY("Locked", "b", get_item_locked, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("Attributes", "a{ss}", get_item_attributes, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("Label", "s", get_item_label, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("Created", "t", get_item_created, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Modified", "t", get_item_modified, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_VTABLE_END
};

const sd_bus_vtable kSessionVtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("Close", "", "", dbus_sess_close, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_VTABLE_END
};

}  // namespace

SecretServiceImpl::SecretServiceImpl(SecretServiceOptions options,
                                     std::unique_ptr<CredentialStore> store)
    : options_(std::move(options)), store_(std::move(store)) {
    if (!store_) {
        store_ = CredentialStore::create(options_.storage_options);
    }
}

SecretServiceImpl::~SecretServiceImpl() {
    stop();
    for (auto* s : slots_) {
        sd_bus_slot_unref(s);
    }
    slots_.clear();
    if (bus_) {
        sd_bus_flush_close_unref(bus_);
        bus_ = nullptr;
    }
}

Result SecretServiceImpl::init_bus() {
    if (bus_) return Result::success();

    int r = 0;
    if (!options_.bus_address.empty()) {
        r = sd_bus_new(&bus_);
        if (r >= 0) r = sd_bus_set_address(bus_, options_.bus_address.c_str());
        if (r >= 0) r = sd_bus_set_bus_client(bus_, 1);
        if (r >= 0) r = sd_bus_start(bus_);
    } else {
        r = sd_bus_open_user(&bus_);
    }

    if (r < 0 || !bus_) {
        return Result::failure("Failed to connect to D-Bus: " + std::string(strerror(-r)));
    }

    if (options_.request_well_known_name) {
        sd_bus_request_name(bus_, "org.freedesktop.secrets", 0);
    }

    // Initialize default collection
    create_collection("default", options_.default_collection_label, "default");

    // Register /org/freedesktop/secrets vtable
    sd_bus_slot* slot = nullptr;
    r = sd_bus_add_object_vtable(bus_, &slot,
                                 "/org/freedesktop/secrets",
                                 "org.freedesktop.Secret.Service",
                                 kSecretServiceVtable, this);
    if (r < 0) return Result::failure("Failed to export Secret.Service vtable");
    slots_.push_back(slot);

    // Register collection fallback vtable
    slot = nullptr;
    r = sd_bus_add_fallback_vtable(bus_, &slot,
                                   "/org/freedesktop/secrets/collection",
                                   "org.freedesktop.Secret.Collection",
                                   kCollectionVtable, find_collection_obj, this);
    if (r < 0) return Result::failure("Failed to export Secret.Collection vtable");
    slots_.push_back(slot);

    // Register alias fallback vtable for Collection
    slot = nullptr;
    r = sd_bus_add_fallback_vtable(bus_, &slot,
                                   "/org/freedesktop/secrets/aliases",
                                   "org.freedesktop.Secret.Collection",
                                   kCollectionVtable, find_collection_obj, this);
    if (r >= 0) slots_.push_back(slot);

    // Register item fallback vtable
    slot = nullptr;
    r = sd_bus_add_fallback_vtable(bus_, &slot,
                                   "/org/freedesktop/secrets/collection",
                                   "org.freedesktop.Secret.Item",
                                   kItemVtable, find_item_obj, this);
    if (r < 0) return Result::failure("Failed to export Secret.Item vtable");
    slots_.push_back(slot);

    // Register session fallback vtable
    slot = nullptr;
    r = sd_bus_add_fallback_vtable(bus_, &slot,
                                   "/org/freedesktop/secrets/session",
                                   "org.freedesktop.Secret.Session",
                                   kSessionVtable, find_session_obj, this);
    if (r < 0) return Result::failure("Failed to export Secret.Session vtable");
    slots_.push_back(slot);

    return Result::success();
}

Result SecretServiceImpl::start() {
    if (running_.load()) return Result::success();

    Result r = init_bus();
    if (!r.ok) return r;

    running_ = true;
    worker_thread_ = std::thread(&SecretServiceImpl::run_worker, this);
    return Result::success();
}

void SecretServiceImpl::stop() {
    if (!running_.exchange(false)) return;
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

bool SecretServiceImpl::process_one(uint64_t timeout_usec) {
    if (!bus_) {
        Result r = init_bus();
        if (!r.ok) return false;
    }
    int r = sd_bus_process(bus_, nullptr);
    if (r > 0) return true;
    r = sd_bus_wait(bus_, timeout_usec);
    if (r < 0) return false;
    return sd_bus_process(bus_, nullptr) > 0;
}

void SecretServiceImpl::run_worker() {
    while (running_.load()) {
        int r = sd_bus_process(bus_, nullptr);
        if (r > 0) continue;
        sd_bus_wait(bus_, 20000); // 20ms
    }
}

std::shared_ptr<SecretCollection> SecretServiceImpl::find_collection(const std::string& path_or_alias) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = collections_.find(path_or_alias);
    if (it != collections_.end()) return it->second;

    auto it_alias = aliases_.find(path_or_alias);
    if (it_alias != aliases_.end()) {
        auto it_target = collections_.find(it_alias->second);
        if (it_target != collections_.end()) return it_target->second;
    }

    // Try finding by alias prefix /org/freedesktop/secrets/aliases/<name>
    const std::string alias_prefix = "/org/freedesktop/secrets/aliases/";
    if (path_or_alias.rfind(alias_prefix, 0) == 0) {
        std::string alias_name = path_or_alias.substr(alias_prefix.size());
        auto it_a = aliases_.find(alias_name);
        if (it_a != aliases_.end()) {
            auto it_target = collections_.find(it_a->second);
            if (it_target != collections_.end()) return it_target->second;
        }
    }
    return nullptr;
}

std::shared_ptr<SecretItem> SecretServiceImpl::find_item(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [_, coll] : collections_) {
        auto item = coll->find_item_by_path(path);
        if (item) return item;
    }
    return nullptr;
}

std::shared_ptr<SecretCollection> SecretServiceImpl::create_collection(
    const std::string& id, const std::string& label, const std::string& alias) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string path = "/org/freedesktop/secrets/collection/" + id;
    auto coll = std::make_shared<SecretCollection>(id, path, label, store_);
    coll->set_service(this);
    collections_[path] = coll;
    if (!alias.empty()) {
        aliases_[alias] = path;
    }
    return coll;
}

bool SecretServiceImpl::delete_collection(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (path == "/org/freedesktop/secrets/collection/default") {
        return false; // Do not delete default collection
    }
    return collections_.erase(path) > 0;
}

std::vector<std::string> SecretServiceImpl::list_collection_paths() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> res;
    res.reserve(collections_.size());
    for (const auto& [p, _] : collections_) {
        res.push_back(p);
    }
    return res;
}

std::vector<std::string> SecretServiceImpl::list_item_paths(const std::string& collection_path) const {
    auto coll = find_collection(collection_path);
    if (!coll) return {};
    return coll->item_paths();
}

}  // namespace brocred::secret_service
