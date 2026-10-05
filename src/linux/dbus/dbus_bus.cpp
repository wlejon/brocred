#include "linux/dbus/dbus_bus.h"

#include <cstdlib>
#include <cstring>
#include <unistd.h>

namespace brocred::linux_dbus {

namespace {

void record_error(sd_bus_error* err, const char* fallback, std::string* out) {
    if (!out) return;
    if (err && err->message) {
        *out = err->name ? std::string(err->name) + ": " + err->message : err->message;
    } else {
        *out = fallback;
    }
}

}  // namespace

BusConnection::BusConnection(sd_bus* bus) : bus_(bus) {}

BusConnection::~BusConnection() {
    if (bus_) {
        sd_bus_flush_close_unref(bus_);
        bus_ = nullptr;
    }
}

std::unique_ptr<BusConnection> BusConnection::open(BusType type, const std::string& address) {
    sd_bus* bus = nullptr;
    int r = 0;

    if (type == BusType::Address || (!address.empty() && type != BusType::System)) {
        r = sd_bus_new(&bus);
        if (r >= 0) r = sd_bus_set_address(bus, address.c_str());
        if (r >= 0) r = sd_bus_set_bus_client(bus, 1);
        if (r >= 0) r = sd_bus_start(bus);
    } else if (type == BusType::System) {
        r = sd_bus_open_system(&bus);
    } else {
        // User session bus
        r = sd_bus_open_user(&bus);
        if (r < 0) {
            // Check fallback path /run/user/<uid>/bus
            std::string user_bus = "/run/user/" + std::to_string(getuid()) + "/bus";
            if (access(user_bus.c_str(), R_OK | W_OK) == 0) {
                std::string addr = "unix:path=" + user_bus;
                r = sd_bus_new(&bus);
                if (r >= 0) r = sd_bus_set_address(bus, addr.c_str());
                if (r >= 0) r = sd_bus_set_bus_client(bus, 1);
                if (r >= 0) r = sd_bus_start(bus);
            }
        }
    }

    if (r < 0 || !bus) {
        if (bus) sd_bus_unref(bus);
        return nullptr;
    }
    sd_bus_set_method_call_timeout(bus, 2000000);
    return std::unique_ptr<BusConnection>(new BusConnection(bus));
}

bool BusConnection::has_owner(const std::string& name) {
    if (!bus_) return false;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message* reply = nullptr;
    int r = sd_bus_call_method(bus_,
                               "org.freedesktop.DBus",
                               "/org/freedesktop/DBus",
                               "org.freedesktop.DBus",
                               "NameHasOwner",
                               &error,
                               &reply,
                               "s",
                               name.c_str());
    int has_owner_val = 0;
    if (r >= 0 && reply) {
        sd_bus_message_read(reply, "b", &has_owner_val);
        sd_bus_message_unref(reply);
    }
    sd_bus_error_free(&error);
    return r >= 0 && has_owner_val != 0;
}

bool BusConnection::secret_service_open_session(std::string& out_session_path, std::string* error) {
    if (!bus_) return false;
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message* reply = nullptr;

    int r = sd_bus_call_method(bus_,
                               "org.freedesktop.secrets",
                               "/org/freedesktop/secrets",
                               "org.freedesktop.Secret.Service",
                               "OpenSession",
                               &err,
                               &reply,
                               "sv",
                               "plain",
                               "s",
                               "");
    if (r < 0) {
        record_error(&err, "OpenSession failed", error);
        sd_bus_error_free(&err);
        return false;
    }

    const char* path = nullptr;
    r = sd_bus_message_skip(reply, "v");
    if (r >= 0) {
        r = sd_bus_message_read(reply, "o", &path);
    }

    if (r >= 0 && path) {
        out_session_path = path;
    } else {
        if (error) *error = "Failed to parse OpenSession reply";
    }

    sd_bus_message_unref(reply);
    sd_bus_error_free(&err);
    return r >= 0 && path != nullptr;
}

bool BusConnection::secret_service_create_item(const std::string& collection_path,
                                              const std::string& session_path,
                                              const std::string& label,
                                              const std::map<std::string, std::string>& attributes,
                                              const std::string& secret_value,
                                              bool replace,
                                              std::string& out_item_path,
                                              std::string* error) {
    if (!bus_) return false;
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message* m = nullptr;

    const char* coll = collection_path.empty() ? "/org/freedesktop/secrets/aliases/default"
                                               : collection_path.c_str();

    int r = sd_bus_message_new_method_call(bus_, &m,
                                           "org.freedesktop.secrets",
                                           coll,
                                           "org.freedesktop.Secret.Collection",
                                           "CreateItem");
    if (r < 0) return false;

    // Dict a{sv} of properties
    r = sd_bus_message_open_container(m, 'a', "{sv}");
    if (r >= 0) {
        // Label
        r = sd_bus_message_open_container(m, 'e', "sv");
        if (r >= 0) {
            sd_bus_message_append(m, "s", "org.freedesktop.Secret.Item.Label");
            sd_bus_message_open_container(m, 'v', "s");
            sd_bus_message_append(m, "s", label.c_str());
            sd_bus_message_close_container(m);
            sd_bus_message_close_container(m);
        }

        // Attributes
        r = sd_bus_message_open_container(m, 'e', "sv");
        if (r >= 0) {
            sd_bus_message_append(m, "s", "org.freedesktop.Secret.Item.Attributes");
            sd_bus_message_open_container(m, 'v', "a{ss}");
            sd_bus_message_open_container(m, 'a', "{ss}");
            for (const auto& [k, v] : attributes) {
                sd_bus_message_append(m, "{ss}", k.c_str(), v.c_str());
            }
            sd_bus_message_close_container(m); // a{ss}
            sd_bus_message_close_container(m); // v
            sd_bus_message_close_container(m); // e
        }
        sd_bus_message_close_container(m); // a{sv}
    }

    // Struct Secret: (oayays)
    if (r >= 0) {
        r = sd_bus_message_open_container(m, 'r', "oayays");
        if (r >= 0) {
            sd_bus_message_append(m, "o", session_path.c_str());
            // parameters empty byte array
            sd_bus_message_append_array(m, 'y', nullptr, 0);
            // secret value
            sd_bus_message_append_array(m, 'y', secret_value.data(), secret_value.size());
            // content_type
            sd_bus_message_append(m, "s", "text/plain");
            sd_bus_message_close_container(m);
        }
    }

    // replace boolean
    if (r >= 0) {
        sd_bus_message_append(m, "b", replace ? 1 : 0);
    }

    sd_bus_message* reply = nullptr;
    r = sd_bus_call(bus_, m, 0, &err, &reply);
    sd_bus_message_unref(m);

    if (r < 0) {
        record_error(&err, "CreateItem call failed", error);
        sd_bus_error_free(&err);
        return false;
    }

    const char* item_path = nullptr;
    const char* prompt_path = nullptr;
    r = sd_bus_message_read(reply, "oo", &item_path, &prompt_path);
    if (r >= 0 && item_path && std::strcmp(item_path, "/") != 0) {
        out_item_path = item_path;
    } else {
        if (error) *error = "CreateItem requires prompt or returned empty path";
    }

    sd_bus_message_unref(reply);
    sd_bus_error_free(&err);
    return r >= 0 && !out_item_path.empty();
}

bool BusConnection::secret_service_search_items(const std::map<std::string, std::string>& attributes,
                                                std::vector<std::string>& out_unlocked,
                                                std::vector<std::string>& out_locked,
                                                std::string* error) {
    if (!bus_) return false;
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message* m = nullptr;

    int r = sd_bus_message_new_method_call(bus_, &m,
                                           "org.freedesktop.secrets",
                                           "/org/freedesktop/secrets",
                                           "org.freedesktop.Secret.Service",
                                           "SearchItems");
    if (r < 0) return false;

    r = sd_bus_message_open_container(m, 'a', "{ss}");
    for (const auto& [k, v] : attributes) {
        sd_bus_message_append(m, "{ss}", k.c_str(), v.c_str());
    }
    sd_bus_message_close_container(m);

    sd_bus_message* reply = nullptr;
    r = sd_bus_call(bus_, m, 0, &err, &reply);
    sd_bus_message_unref(m);

    if (r < 0) {
        record_error(&err, "SearchItems failed", error);
        sd_bus_error_free(&err);
        return false;
    }

    // Read (ao, ao)
    r = sd_bus_message_enter_container(reply, 'a', "o");
    if (r > 0) {
        const char* path = nullptr;
        while (sd_bus_message_read(reply, "o", &path) > 0 && path) {
            out_unlocked.push_back(path);
        }
        sd_bus_message_exit_container(reply);
    }

    r = sd_bus_message_enter_container(reply, 'a', "o");
    if (r > 0) {
        const char* path = nullptr;
        while (sd_bus_message_read(reply, "o", &path) > 0 && path) {
            out_locked.push_back(path);
        }
        sd_bus_message_exit_container(reply);
    }

    sd_bus_message_unref(reply);
    sd_bus_error_free(&err);
    return true;
}

bool BusConnection::secret_service_unlock(const std::vector<std::string>& locked_paths,
                                         std::vector<std::string>& out_unlocked,
                                         std::string* error) {
    if (!bus_ || locked_paths.empty()) return true;
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message* m = nullptr;

    int r = sd_bus_message_new_method_call(bus_, &m,
                                           "org.freedesktop.secrets",
                                           "/org/freedesktop/secrets",
                                           "org.freedesktop.Secret.Service",
                                           "Unlock");
    if (r < 0) return false;

    r = sd_bus_message_open_container(m, 'a', "o");
    for (const auto& p : locked_paths) {
        sd_bus_message_append(m, "o", p.c_str());
    }
    sd_bus_message_close_container(m);

    sd_bus_message* reply = nullptr;
    r = sd_bus_call(bus_, m, 0, &err, &reply);
    sd_bus_message_unref(m);

    if (r < 0) {
        record_error(&err, "Unlock failed", error);
        sd_bus_error_free(&err);
        return false;
    }

    r = sd_bus_message_enter_container(reply, 'a', "o");
    if (r > 0) {
        const char* path = nullptr;
        while (sd_bus_message_read(reply, "o", &path) > 0 && path) {
            out_unlocked.push_back(path);
        }
        sd_bus_message_exit_container(reply);
    }

    sd_bus_message_unref(reply);
    sd_bus_error_free(&err);
    return true;
}

bool BusConnection::secret_service_get_secret(const std::string& item_path,
                                             const std::string& session_path,
                                             std::string& out_secret_value,
                                             std::string* error) {
    if (!bus_) return false;
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message* reply = nullptr;

    int r = sd_bus_call_method(bus_,
                               "org.freedesktop.secrets",
                               item_path.c_str(),
                               "org.freedesktop.Secret.Item",
                               "GetSecret",
                               &err,
                               &reply,
                               "o",
                               session_path.c_str());
    if (r < 0) {
        record_error(&err, "GetSecret failed", error);
        sd_bus_error_free(&err);
        return false;
    }

    // Read struct Secret: (oayays)
    r = sd_bus_message_enter_container(reply, 'r', "oayays");
    if (r > 0) {
        const char* s_path = nullptr;
        sd_bus_message_read(reply, "o", &s_path);

        const void* p_data = nullptr;
        size_t p_size = 0;
        sd_bus_message_read_array(reply, 'y', &p_data, &p_size);

        const void* v_data = nullptr;
        size_t v_size = 0;
        sd_bus_message_read_array(reply, 'y', &v_data, &v_size);

        if (v_data && v_size > 0) {
            out_secret_value.assign(reinterpret_cast<const char*>(v_data), v_size);
        } else {
            out_secret_value.clear();
        }

        sd_bus_message_exit_container(reply);
    }

    sd_bus_message_unref(reply);
    sd_bus_error_free(&err);
    return r >= 0;
}

bool BusConnection::secret_service_get_item_attributes(const std::string& item_path,
                                                       std::map<std::string, std::string>& out_attrs,
                                                       std::string* error) {
    if (!bus_) return false;
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message* reply = nullptr;

    int r = sd_bus_call_method(bus_,
                               "org.freedesktop.secrets",
                               item_path.c_str(),
                               "org.freedesktop.DBus.Properties",
                               "Get",
                               &err,
                               &reply,
                               "ss",
                               "org.freedesktop.Secret.Item",
                               "Attributes");
    if (r < 0) {
        record_error(&err, "Get Attributes failed", error);
        sd_bus_error_free(&err);
        return false;
    }

    // Variant containing a{ss}
    r = sd_bus_message_enter_container(reply, 'v', "a{ss}");
    if (r > 0) {
        r = sd_bus_message_enter_container(reply, 'a', "{ss}");
        if (r > 0) {
            const char* k = nullptr;
            const char* v = nullptr;
            while (sd_bus_message_read(reply, "{ss}", &k, &v) > 0 && k && v) {
                out_attrs[k] = v;
            }
            sd_bus_message_exit_container(reply);
        }
        sd_bus_message_exit_container(reply);
    }

    sd_bus_message_unref(reply);
    sd_bus_error_free(&err);
    return r >= 0;
}

bool BusConnection::secret_service_delete_item(const std::string& item_path, std::string* error) {
    if (!bus_) return false;
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message* reply = nullptr;

    int r = sd_bus_call_method(bus_,
                               "org.freedesktop.secrets",
                               item_path.c_str(),
                               "org.freedesktop.Secret.Item",
                               "Delete",
                               &err,
                               &reply,
                               "");
    if (r < 0) {
        record_error(&err, "DeleteItem failed", error);
        sd_bus_error_free(&err);
        return false;
    }

    sd_bus_message_unref(reply);
    sd_bus_error_free(&err);
    return true;
}

bool BusConnection::fprint_get_devices(std::vector<std::string>& out_devices, std::string* error) {
    if (!bus_) return false;
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message* reply = nullptr;

    int r = sd_bus_call_method(bus_,
                               "net.reactivated.Fprint",
                               "/net/reactivated/Fprint/Manager",
                               "net.reactivated.Fprint.Manager",
                               "GetDevices",
                               &err,
                               &reply,
                               "");
    if (r < 0) {
        record_error(&err, "fprint GetDevices failed", error);
        sd_bus_error_free(&err);
        return false;
    }

    r = sd_bus_message_enter_container(reply, 'a', "o");
    if (r > 0) {
        const char* path = nullptr;
        while (sd_bus_message_read(reply, "o", &path) > 0 && path) {
            out_devices.push_back(path);
        }
        sd_bus_message_exit_container(reply);
    }

    sd_bus_message_unref(reply);
    sd_bus_error_free(&err);
    return r >= 0;
}

bool BusConnection::fprint_list_enrolled_fingers(const std::string& device_path,
                                                 const std::string& username,
                                                 std::vector<std::string>& out_fingers,
                                                 std::string* error) {
    if (!bus_) return false;
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message* reply = nullptr;

    int r = sd_bus_call_method(bus_,
                               "net.reactivated.Fprint",
                               device_path.c_str(),
                               "net.reactivated.Fprint.Device",
                               "ListEnrolledFingers",
                               &err,
                               &reply,
                               "s",
                               username.c_str());
    if (r < 0) {
        record_error(&err, "fprint ListEnrolledFingers failed", error);
        sd_bus_error_free(&err);
        return false;
    }

    r = sd_bus_message_enter_container(reply, 'a', "s");
    if (r > 0) {
        const char* finger = nullptr;
        while (sd_bus_message_read(reply, "s", &finger) > 0 && finger) {
            out_fingers.push_back(finger);
        }
        sd_bus_message_exit_container(reply);
    }

    sd_bus_message_unref(reply);
    sd_bus_error_free(&err);
    return r >= 0;
}

}  // namespace brocred::linux_dbus
