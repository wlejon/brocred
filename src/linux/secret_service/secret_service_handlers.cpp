// Implementation of Secret Service D-Bus method handlers.
#include "linux/secret_service/secret_service_impl.h"

#include <cstring>

namespace brocred::secret_service {

namespace {

int reply_secret_struct(sd_bus_message* reply,
                        const std::string& session_path,
                        const std::vector<uint8_t>& parameters,
                        const std::vector<uint8_t>& value,
                        const std::string& content_type) {
    int r = sd_bus_message_open_container(reply, 'r', "oayays");
    if (r < 0) return r;
    r = sd_bus_message_append(reply, "o", session_path.c_str());
    if (r < 0) return r;
    r = sd_bus_message_append_array(reply, 'y', parameters.data(), parameters.size());
    if (r < 0) return r;
    r = sd_bus_message_append_array(reply, 'y', value.data(), value.size());
    if (r < 0) return r;
    r = sd_bus_message_append(reply, "s", content_type.c_str());
    if (r < 0) return r;
    return sd_bus_message_close_container(reply);
}

}  // namespace

int SecretServiceImpl::handle_open_session(sd_bus_message* m, sd_bus_error* ret_error) {
    const char* algorithm = nullptr;
    int r = sd_bus_message_read(m, "s", &algorithm);
    if (r < 0) return r;

    sd_bus_message* reply = nullptr;
    r = sd_bus_message_new_method_return(m, &reply);
    if (r < 0) return r;

    if (std::strcmp(algorithm, "plain") == 0) {
        // Skip input variant
        sd_bus_message_skip(m, "v");

        std::string session_path;
        session_manager_.open_plain_session(&session_path, this);

        // Output variant string ""
        r = sd_bus_message_open_container(reply, 'v', "s");
        if (r >= 0) {
            sd_bus_message_append(reply, "s", "");
            sd_bus_message_close_container(reply);
        }
        sd_bus_message_append(reply, "o", session_path.c_str());
    } else if (std::strcmp(algorithm, "dh-ietf1024-sha256-aes128-cbc-pkcs7") == 0) {
        // Read input variant containing client public key byte array (ay)
        r = sd_bus_message_enter_container(m, 'v', nullptr);
        if (r < 0) {
            sd_bus_message_unref(reply);
            return sd_bus_error_setf(ret_error, "org.freedesktop.DBus.Error.InvalidArgs", "Missing input variant");
        }

        const void* ptr = nullptr;
        size_t size = 0;
        r = sd_bus_message_read_array(m, 'y', &ptr, &size);
        sd_bus_message_exit_container(m);

        if (r < 0 || size == 0) {
            sd_bus_message_unref(reply);
            return sd_bus_error_setf(ret_error, "org.freedesktop.DBus.Error.InvalidArgs", "Missing client public key array");
        }

        std::vector<uint8_t> client_pub(static_cast<const uint8_t*>(ptr),
                                        static_cast<const uint8_t*>(ptr) + size);
        std::vector<uint8_t> server_pub;
        std::string session_path;
        Result res = session_manager_.open_dh_session(client_pub, server_pub, session_path, this);
        if (!res.ok) {
            sd_bus_message_unref(reply);
            return sd_bus_error_setf(ret_error, "org.freedesktop.DBus.Error.InvalidArgs", "%s", res.error.c_str());
        }

        // Output variant byte array
        r = sd_bus_message_open_container(reply, 'v', "ay");
        if (r >= 0) {
            sd_bus_message_append_array(reply, 'y', server_pub.data(), server_pub.size());
            sd_bus_message_close_container(reply);
        }
        sd_bus_message_append(reply, "o", session_path.c_str());
    } else {
        sd_bus_message_unref(reply);
        return sd_bus_error_setf(ret_error, "org.freedesktop.DBus.Error.NotSupported",
                                 "Session algorithm '%s' is not supported", algorithm);
    }

    r = sd_bus_send(bus_, reply, nullptr);
    sd_bus_message_unref(reply);
    return r;
}

int SecretServiceImpl::handle_create_collection(sd_bus_message* m, sd_bus_error* /*ret_error*/) {
    std::string label = "Collection";

    // Read properties a{sv}
    int r = sd_bus_message_enter_container(m, 'a', "{sv}");
    if (r >= 0) {
        while ((r = sd_bus_message_enter_container(m, 'e', "sv")) > 0) {
            const char* prop_name = nullptr;
            sd_bus_message_read(m, "s", &prop_name);
            if (prop_name && std::strcmp(prop_name, "org.freedesktop.Secret.Collection.Label") == 0) {
                sd_bus_message_enter_container(m, 'v', "s");
                const char* lbl = nullptr;
                sd_bus_message_read(m, "s", &lbl);
                if (lbl) label = lbl;
                sd_bus_message_exit_container(m);
            } else {
                sd_bus_message_skip(m, "v");
            }
            sd_bus_message_exit_container(m);
        }
        sd_bus_message_exit_container(m);
    }

    const char* alias = nullptr;
    sd_bus_message_read(m, "s", &alias);
    std::string alias_str = alias ? alias : "";

    std::shared_ptr<SecretCollection> coll;
    if (!alias_str.empty()) {
        coll = find_collection(alias_str);
    }

    if (!coll) {
        std::string id = alias_str.empty() ? "c" + std::to_string(next_collection_id_++) : alias_str;
        coll = create_collection(id, label, alias_str);
    } else {
        coll->set_label(label);
    }

    return sd_bus_reply_method_return(m, "oo", coll->path().c_str(), "/");
}

int SecretServiceImpl::handle_search_items(sd_bus_message* m, sd_bus_error* /*ret_error*/) {
    std::map<std::string, std::string> search_attrs;
    int r = sd_bus_message_enter_container(m, 'a', "{ss}");
    if (r >= 0) {
        while ((r = sd_bus_message_enter_container(m, 'e', "ss")) > 0) {
            const char *k = nullptr, *v = nullptr;
            sd_bus_message_read(m, "ss", &k, &v);
            if (k && v) search_attrs[k] = v;
            sd_bus_message_exit_container(m);
        }
        sd_bus_message_exit_container(m);
    }

    std::vector<std::string> unlocked_paths;
    std::vector<std::string> locked_paths;

    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [_, coll] : collections_) {
        auto items = coll->search_items(search_attrs);
        for (const auto& item : items) {
            if (coll->is_locked() || item->is_locked()) {
                locked_paths.push_back(item->path());
            } else {
                unlocked_paths.push_back(item->path());
            }
        }
    }

    sd_bus_message* reply = nullptr;
    r = sd_bus_message_new_method_return(m, &reply);
    if (r < 0) return r;

    // unlocked ao
    r = sd_bus_message_open_container(reply, 'a', "o");
    if (r >= 0) {
        for (const auto& p : unlocked_paths) sd_bus_message_append(reply, "o", p.c_str());
        sd_bus_message_close_container(reply);
    }

    // locked ao
    r = sd_bus_message_open_container(reply, 'a', "o");
    if (r >= 0) {
        for (const auto& p : locked_paths) sd_bus_message_append(reply, "o", p.c_str());
        sd_bus_message_close_container(reply);
    }

    r = sd_bus_send(bus_, reply, nullptr);
    sd_bus_message_unref(reply);
    return r;
}

int SecretServiceImpl::handle_unlock(sd_bus_message* m, sd_bus_error* /*ret_error*/) {
    std::vector<std::string> unlocked;
    int r = sd_bus_message_enter_container(m, 'a', "o");
    if (r >= 0) {
        const char* obj_path = nullptr;
        while ((r = sd_bus_message_read(m, "o", &obj_path)) > 0) {
            if (!obj_path) continue;
            auto coll = find_collection(obj_path);
            if (coll) {
                coll->set_locked(false);
                unlocked.push_back(obj_path);
            } else {
                auto item = find_item(obj_path);
                if (item) {
                    item->set_locked(false);
                    unlocked.push_back(obj_path);
                }
            }
        }
        sd_bus_message_exit_container(m);
    }

    sd_bus_message* reply = nullptr;
    r = sd_bus_message_new_method_return(m, &reply);
    if (r < 0) return r;

    r = sd_bus_message_open_container(reply, 'a', "o");
    if (r >= 0) {
        for (const auto& p : unlocked) sd_bus_message_append(reply, "o", p.c_str());
        sd_bus_message_close_container(reply);
    }
    sd_bus_message_append(reply, "o", "/"); // prompt /

    r = sd_bus_send(bus_, reply, nullptr);
    sd_bus_message_unref(reply);
    return r;
}

int SecretServiceImpl::handle_lock(sd_bus_message* m, sd_bus_error* /*ret_error*/) {
    std::vector<std::string> locked;
    int r = sd_bus_message_enter_container(m, 'a', "o");
    if (r >= 0) {
        const char* obj_path = nullptr;
        while ((r = sd_bus_message_read(m, "o", &obj_path)) > 0) {
            if (!obj_path) continue;
            auto coll = find_collection(obj_path);
            if (coll) {
                coll->set_locked(true);
                locked.push_back(obj_path);
            } else {
                auto item = find_item(obj_path);
                if (item) {
                    item->set_locked(true);
                    locked.push_back(obj_path);
                }
            }
        }
        sd_bus_message_exit_container(m);
    }

    sd_bus_message* reply = nullptr;
    r = sd_bus_message_new_method_return(m, &reply);
    if (r < 0) return r;

    r = sd_bus_message_open_container(reply, 'a', "o");
    if (r >= 0) {
        for (const auto& p : locked) sd_bus_message_append(reply, "o", p.c_str());
        sd_bus_message_close_container(reply);
    }
    sd_bus_message_append(reply, "o", "/");

    r = sd_bus_send(bus_, reply, nullptr);
    sd_bus_message_unref(reply);
    return r;
}

int SecretServiceImpl::handle_get_secrets(sd_bus_message* m, sd_bus_error* ret_error) {
    std::vector<std::string> item_paths;
    int r = sd_bus_message_enter_container(m, 'a', "o");
    if (r >= 0) {
        const char* obj_path = nullptr;
        while ((r = sd_bus_message_read(m, "o", &obj_path)) > 0) {
            if (obj_path) item_paths.push_back(obj_path);
        }
        sd_bus_message_exit_container(m);
    }

    const char* session_path = nullptr;
    sd_bus_message_read(m, "o", &session_path);
    if (!session_path) {
        return sd_bus_error_setf(ret_error, "org.freedesktop.Secret.Error.NoSession", "Session path missing");
    }

    auto sess = session_manager_.find_session(session_path);
    if (!sess) {
        return sd_bus_error_setf(ret_error, "org.freedesktop.Secret.Error.NoSession",
                                 "Session '%s' does not exist", session_path);
    }

    sd_bus_message* reply = nullptr;
    r = sd_bus_message_new_method_return(m, &reply);
    if (r < 0) return r;

    // a{o(oayays)}
    r = sd_bus_message_open_container(reply, 'a', "{o(oayays)}");
    if (r >= 0) {
        for (const auto& path : item_paths) {
            auto item = find_item(path);
            if (!item || item->is_locked()) continue;

            std::vector<uint8_t> params, val;
            std::string ctype;
            if (!sess->encode_secret(item->secret(), item->content_type(), params, val, ctype).ok) {
                continue;
            }

            r = sd_bus_message_open_container(reply, 'e', "o(oayays)");
            if (r >= 0) {
                sd_bus_message_append(reply, "o", path.c_str());
                reply_secret_struct(reply, session_path, params, val, ctype);
                sd_bus_message_close_container(reply);
            }
        }
        sd_bus_message_close_container(reply);
    }

    r = sd_bus_send(bus_, reply, nullptr);
    sd_bus_message_unref(reply);
    return r;
}

int SecretServiceImpl::handle_read_alias(sd_bus_message* m, sd_bus_error* /*ret_error*/) {
    const char* name = nullptr;
    sd_bus_message_read(m, "s", &name);
    std::string name_str = name ? name : "";

    std::string target = "/";
    if (name_str == "default") {
        target = "/org/freedesktop/secrets/collection/default";
    }

    std::lock_guard<std::mutex> lock(mutex_);
    auto it = aliases_.find(name_str);
    if (it != aliases_.end()) {
        target = it->second;
    }

    return sd_bus_reply_method_return(m, "o", target.c_str());
}

int SecretServiceImpl::handle_set_alias(sd_bus_message* m, sd_bus_error* /*ret_error*/) {
    const char *name = nullptr, *coll = nullptr;
    sd_bus_message_read(m, "so", &name, &coll);
    if (name) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!coll || std::strcmp(coll, "/") == 0) {
            aliases_.erase(name);
        } else {
            aliases_[name] = coll;
        }
    }
    return sd_bus_reply_method_return(m, "");
}

int SecretServiceImpl::handle_collection_create_item(sd_bus_message* m, void* userdata, sd_bus_error* ret_error) {
    auto* coll = static_cast<SecretCollection*>(userdata);
    std::string label = "Item";
    std::map<std::string, std::string> attributes;

    // Read properties a{sv}
    int r = sd_bus_message_enter_container(m, 'a', "{sv}");
    if (r >= 0) {
        while ((r = sd_bus_message_enter_container(m, 'e', "sv")) > 0) {
            const char* prop_name = nullptr;
            sd_bus_message_read(m, "s", &prop_name);
            if (prop_name && std::strcmp(prop_name, "org.freedesktop.Secret.Item.Label") == 0) {
                sd_bus_message_enter_container(m, 'v', "s");
                const char* lbl = nullptr;
                sd_bus_message_read(m, "s", &lbl);
                if (lbl) label = lbl;
                sd_bus_message_exit_container(m);
            } else if (prop_name && std::strcmp(prop_name, "org.freedesktop.Secret.Item.Attributes") == 0) {
                sd_bus_message_enter_container(m, 'v', "a{ss}");
                sd_bus_message_enter_container(m, 'a', "{ss}");
                while (sd_bus_message_enter_container(m, 'e', "ss") > 0) {
                    const char *k = nullptr, *v = nullptr;
                    sd_bus_message_read(m, "ss", &k, &v);
                    if (k && v) attributes[k] = v;
                    sd_bus_message_exit_container(m);
                }
                sd_bus_message_exit_container(m);
                sd_bus_message_exit_container(m);
            } else {
                sd_bus_message_skip(m, "v");
            }
            sd_bus_message_exit_container(m);
        }
        sd_bus_message_exit_container(m);
    }

    // Read Secret struct (oayays)
    r = sd_bus_message_enter_container(m, 'r', "oayays");
    if (r < 0) {
        return sd_bus_error_setf(ret_error, "org.freedesktop.DBus.Error.InvalidArgs", "Missing Secret struct");
    }

    const char* sess_path = nullptr;
    sd_bus_message_read(m, "o", &sess_path);

    const void* param_ptr = nullptr;
    size_t param_size = 0;
    sd_bus_message_read_array(m, 'y', &param_ptr, &param_size);

    const void* val_ptr = nullptr;
    size_t val_size = 0;
    sd_bus_message_read_array(m, 'y', &val_ptr, &val_size);

    const char* ctype = nullptr;
    sd_bus_message_read(m, "s", &ctype);
    sd_bus_message_exit_container(m);

    int replace = 0;
    sd_bus_message_read(m, "b", &replace);

    auto sess = session_manager_.find_session(sess_path ? sess_path : "");
    if (!sess) {
        return sd_bus_error_setf(ret_error, "org.freedesktop.Secret.Error.NoSession",
                                 "Session '%s' does not exist", sess_path ? sess_path : "");
    }

    std::vector<uint8_t> params(static_cast<const uint8_t*>(param_ptr),
                                static_cast<const uint8_t*>(param_ptr) + param_size);
    std::vector<uint8_t> val(static_cast<const uint8_t*>(val_ptr),
                             static_cast<const uint8_t*>(val_ptr) + val_size);

    std::string plain_secret;
    Result dec_res = sess->decode_secret(params, val, plain_secret);
    if (!dec_res.ok) {
        return sd_bus_error_setf(ret_error, "org.freedesktop.DBus.Error.InvalidArgs",
                                 "Failed to decrypt secret: %s", dec_res.error.c_str());
    }

    auto item = coll->create_or_replace_item(label, attributes, plain_secret,
                                            ctype ? ctype : "text/plain", replace != 0);

    return sd_bus_reply_method_return(m, "oo", item->path().c_str(), "/");
}

int SecretServiceImpl::handle_collection_delete(sd_bus_message* m, void* userdata, sd_bus_error* /*ret_error*/) {
    auto* coll = static_cast<SecretCollection*>(userdata);
    delete_collection(coll->path());
    return sd_bus_reply_method_return(m, "o", "/");
}

int SecretServiceImpl::handle_collection_search_items(sd_bus_message* m, void* userdata, sd_bus_error* /*ret_error*/) {
    auto* coll = static_cast<SecretCollection*>(userdata);
    std::map<std::string, std::string> search_attrs;
    int r = sd_bus_message_enter_container(m, 'a', "{ss}");
    if (r >= 0) {
        while ((r = sd_bus_message_enter_container(m, 'e', "ss")) > 0) {
            const char *k = nullptr, *v = nullptr;
            sd_bus_message_read(m, "ss", &k, &v);
            if (k && v) search_attrs[k] = v;
            sd_bus_message_exit_container(m);
        }
        sd_bus_message_exit_container(m);
    }

    auto items = coll->search_items(search_attrs);
    sd_bus_message* reply = nullptr;
    r = sd_bus_message_new_method_return(m, &reply);
    if (r < 0) return r;

    r = sd_bus_message_open_container(reply, 'a', "o");
    if (r >= 0) {
        for (const auto& item : items) {
            sd_bus_message_append(reply, "o", item->path().c_str());
        }
        sd_bus_message_close_container(reply);
    }

    r = sd_bus_send(bus_, reply, nullptr);
    sd_bus_message_unref(reply);
    return r;
}

int SecretServiceImpl::handle_item_get_secret(sd_bus_message* m, void* userdata, sd_bus_error* ret_error) {
    auto* item = static_cast<SecretItem*>(userdata);
    if (item->is_locked()) {
        return sd_bus_error_setf(ret_error, "org.freedesktop.Secret.Error.IsLocked", "Item is locked");
    }

    const char* sess_path = nullptr;
    sd_bus_message_read(m, "o", &sess_path);
    auto sess = session_manager_.find_session(sess_path ? sess_path : "");
    if (!sess) {
        return sd_bus_error_setf(ret_error, "org.freedesktop.Secret.Error.NoSession",
                                 "Session '%s' does not exist", sess_path ? sess_path : "");
    }

    std::vector<uint8_t> params, val;
    std::string ctype;
    Result enc_res = sess->encode_secret(item->secret(), item->content_type(), params, val, ctype);
    if (!enc_res.ok) {
        return sd_bus_error_setf(ret_error, "org.freedesktop.DBus.Error.Failed",
                                 "Failed to encode secret: %s", enc_res.error.c_str());
    }

    sd_bus_message* reply = nullptr;
    int r = sd_bus_message_new_method_return(m, &reply);
    if (r < 0) return r;

    reply_secret_struct(reply, sess_path, params, val, ctype);
    r = sd_bus_send(bus_, reply, nullptr);
    sd_bus_message_unref(reply);
    return r;
}

int SecretServiceImpl::handle_item_set_secret(sd_bus_message* m, void* userdata, sd_bus_error* ret_error) {
    auto* item = static_cast<SecretItem*>(userdata);
    if (item->is_locked()) {
        return sd_bus_error_setf(ret_error, "org.freedesktop.Secret.Error.IsLocked", "Item is locked");
    }

    int r = sd_bus_message_enter_container(m, 'r', "oayays");
    if (r < 0) {
        return sd_bus_error_setf(ret_error, "org.freedesktop.DBus.Error.InvalidArgs", "Missing Secret struct");
    }

    const char* sess_path = nullptr;
    sd_bus_message_read(m, "o", &sess_path);

    const void* param_ptr = nullptr;
    size_t param_size = 0;
    sd_bus_message_read_array(m, 'y', &param_ptr, &param_size);

    const void* val_ptr = nullptr;
    size_t val_size = 0;
    sd_bus_message_read_array(m, 'y', &val_ptr, &val_size);

    const char* ctype = nullptr;
    sd_bus_message_read(m, "s", &ctype);
    sd_bus_message_exit_container(m);

    auto sess = session_manager_.find_session(sess_path ? sess_path : "");
    if (!sess) {
        return sd_bus_error_setf(ret_error, "org.freedesktop.Secret.Error.NoSession",
                                 "Session '%s' does not exist", sess_path ? sess_path : "");
    }

    std::vector<uint8_t> params(static_cast<const uint8_t*>(param_ptr),
                                static_cast<const uint8_t*>(param_ptr) + param_size);
    std::vector<uint8_t> val(static_cast<const uint8_t*>(val_ptr),
                             static_cast<const uint8_t*>(val_ptr) + val_size);

    std::string plain;
    Result dec_res = sess->decode_secret(params, val, plain);
    if (!dec_res.ok) {
        return sd_bus_error_setf(ret_error, "org.freedesktop.DBus.Error.InvalidArgs",
                                 "Failed to decrypt secret: %s", dec_res.error.c_str());
    }

    item->set_secret(plain);
    if (ctype && *ctype) item->set_content_type(ctype);

    return sd_bus_reply_method_return(m, "");
}

int SecretServiceImpl::handle_item_delete(sd_bus_message* m, void* userdata, sd_bus_error* /*ret_error*/) {
    auto* item = static_cast<SecretItem*>(userdata);
    auto coll = find_collection(item->collection_id());
    if (coll) {
        coll->delete_item(item->id());
    }
    return sd_bus_reply_method_return(m, "o", "/");
}

int SecretServiceImpl::handle_session_close(sd_bus_message* m, void* /*userdata*/, sd_bus_error* /*ret_error*/) {
    const char* path = sd_bus_message_get_path(m);
    if (path) {
        session_manager_.close_session(path);
    }
    return sd_bus_reply_method_return(m, "");
}

}  // namespace brocred::secret_service
