#include "linux/dbus/dbus_bus.h"

#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <utility>

namespace brocred::linux_dbus {

namespace {

void record_error(const brodbus::Error& err, const char* fallback, std::string* out) {
    if (!out) return;
    std::string s = err.to_string();
    if (!s.empty()) {
        *out = std::move(s);
    } else {
        *out = fallback ? fallback : "";
    }
}

}  // namespace

BusConnection::BusConnection(brodbus::Bus bus) : bus_(std::move(bus)) {}

BusConnection::BusConnection(sd_bus* bus) : bus_(bus) {}

BusConnection::~BusConnection() = default;

std::unique_ptr<BusConnection> BusConnection::open(BusType type, const std::string& address) {
    std::string err;
    std::unique_ptr<brodbus::Bus> bus;

    if (type == BusType::Address || (!address.empty() && type != BusType::System)) {
        bus = brodbus::Bus::open_address(address, &err);
    } else if (type == BusType::System) {
        bus = brodbus::Bus::open_system(&err);
    } else {
        bus = brodbus::Bus::open_user(&err);
    }

    if (!bus || !bus->is_valid()) {
        return nullptr;
    }

    sd_bus_set_method_call_timeout(bus->raw(), 2000000);
    return std::unique_ptr<BusConnection>(new BusConnection(std::move(*bus)));
}

bool BusConnection::has_owner(const std::string& name) {
    if (!bus_.is_valid()) return false;
    bool has_owner_val = false;
    bool ok = bus_.call_method(
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "NameHasOwner",
        [&](brodbus::Message& m) { m.append_string(name); },
        [&](brodbus::Message& reply) { reply.read_bool(&has_owner_val); });
    return ok && has_owner_val;
}

bool BusConnection::secret_service_open_session(std::string& out_session_path, std::string* error) {
    if (!bus_.is_valid()) return false;

    brodbus::Message m = bus_.new_method_call(
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
        "OpenSession");
    if (!m) {
        if (error) *error = "OpenSession failed to create message";
        return false;
    }

    m.append_string("plain");
    m.open_container('v', "s");
    m.append_string("");
    m.close_container();

    brodbus::Error err;
    brodbus::Message reply = bus_.call(m, 0, &err);
    if (!reply) {
        record_error(err, "OpenSession failed", error);
        return false;
    }

    int r = sd_bus_message_skip(reply.raw(), "v");
    const char* path = nullptr;
    if (r >= 0) {
        r = sd_bus_message_read(reply.raw(), "o", &path);
    }

    if (r >= 0 && path) {
        out_session_path = path;
    } else {
        if (error) *error = "Failed to parse OpenSession reply";
        return false;
    }

    return true;
}

bool BusConnection::secret_service_create_item(const std::string& collection_path,
                                              const std::string& session_path,
                                              const std::string& label,
                                              const std::map<std::string, std::string>& attributes,
                                              const std::string& secret_value,
                                              bool replace,
                                              std::string& out_item_path,
                                              std::string* error) {
    if (!bus_.is_valid()) return false;

    const std::string coll = collection_path.empty() ? "/org/freedesktop/secrets/aliases/default"
                                                     : collection_path;

    brodbus::Message m = bus_.new_method_call(
        "org.freedesktop.secrets",
        coll,
        "org.freedesktop.Secret.Collection",
        "CreateItem");
    if (!m) return false;

    // Dict a{sv} of properties
    m.open_container('a', "{sv}");
    {
        // Label
        m.open_container('e', "sv");
        m.append_string("org.freedesktop.Secret.Item.Label");
        m.open_container('v', "s");
        m.append_string(label);
        m.close_container();
        m.close_container();

        // Attributes
        m.open_container('e', "sv");
        m.append_string("org.freedesktop.Secret.Item.Attributes");
        m.open_container('v', "a{ss}");
        m.open_container('a', "{ss}");
        for (const auto& [k, v] : attributes) {
            sd_bus_message_append(m.raw(), "{ss}", k.c_str(), v.c_str());
        }
        m.close_container(); // a{ss}
        m.close_container(); // v
        m.close_container(); // e
    }
    m.close_container(); // a{sv}

    // Struct Secret: (oayays)
    m.open_container('r', "oayays");
    m.append_object_path(session_path);
    // parameters empty byte array
    sd_bus_message_append_array(m.raw(), 'y', nullptr, 0);
    // secret value
    sd_bus_message_append_array(m.raw(), 'y', secret_value.data(), secret_value.size());
    // content_type
    m.append_string("text/plain");
    m.close_container();

    // replace boolean
    m.append_bool(replace);

    brodbus::Error err;
    brodbus::Message reply = bus_.call(m, 0, &err);
    if (!reply) {
        record_error(err, "CreateItem call failed", error);
        return false;
    }

    const char* item_path = nullptr;
    const char* prompt_path = nullptr;
    int r = sd_bus_message_read(reply.raw(), "oo", &item_path, &prompt_path);
    if (r >= 0 && item_path && std::strcmp(item_path, "/") != 0) {
        out_item_path = item_path;
    } else {
        if (error) *error = "CreateItem requires prompt or returned empty path";
    }

    return r >= 0 && !out_item_path.empty();
}

bool BusConnection::secret_service_search_items(const std::map<std::string, std::string>& attributes,
                                                std::vector<std::string>& out_unlocked,
                                                std::vector<std::string>& out_locked,
                                                std::string* error) {
    if (!bus_.is_valid()) return false;

    brodbus::Message m = bus_.new_method_call(
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
        "SearchItems");
    if (!m) return false;

    m.open_container('a', "{ss}");
    for (const auto& [k, v] : attributes) {
        sd_bus_message_append(m.raw(), "{ss}", k.c_str(), v.c_str());
    }
    m.close_container();

    brodbus::Error err;
    brodbus::Message reply = bus_.call(m, 0, &err);
    if (!reply) {
        record_error(err, "SearchItems failed", error);
        return false;
    }

    out_unlocked.clear();
    out_locked.clear();

    if (reply.enter_container('a', "o") > 0) {
        const char* path = nullptr;
        while (sd_bus_message_read(reply.raw(), "o", &path) > 0 && path) {
            out_unlocked.push_back(path);
        }
        reply.exit_container();
    }

    if (reply.enter_container('a', "o") > 0) {
        const char* path = nullptr;
        while (sd_bus_message_read(reply.raw(), "o", &path) > 0 && path) {
            out_locked.push_back(path);
        }
        reply.exit_container();
    }

    return true;
}

bool BusConnection::secret_service_unlock(const std::vector<std::string>& locked_paths,
                                         std::vector<std::string>& out_unlocked,
                                         std::string* error) {
    if (!bus_.is_valid() || locked_paths.empty()) return true;

    brodbus::Message m = bus_.new_method_call(
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
        "Unlock");
    if (!m) return false;

    m.open_container('a', "o");
    for (const auto& p : locked_paths) {
        m.append_object_path(p);
    }
    m.close_container();

    brodbus::Error err;
    brodbus::Message reply = bus_.call(m, 0, &err);
    if (!reply) {
        record_error(err, "Unlock failed", error);
        return false;
    }

    out_unlocked.clear();
    if (reply.enter_container('a', "o") > 0) {
        const char* path = nullptr;
        while (sd_bus_message_read(reply.raw(), "o", &path) > 0 && path) {
            out_unlocked.push_back(path);
        }
        reply.exit_container();
    }

    return true;
}

bool BusConnection::secret_service_get_secret(const std::string& item_path,
                                             const std::string& session_path,
                                             std::string& out_secret_value,
                                             std::string* error) {
    if (!bus_.is_valid()) return false;

    brodbus::Message m = bus_.new_method_call(
        "org.freedesktop.secrets",
        item_path,
        "org.freedesktop.Secret.Item",
        "GetSecret");
    if (!m) return false;

    m.append_object_path(session_path);

    brodbus::Error err;
    brodbus::Message reply = bus_.call(m, 0, &err);
    if (!reply) {
        record_error(err, "GetSecret failed", error);
        return false;
    }

    // Read struct Secret: (oayays)
    if (reply.enter_container('r', "oayays") > 0) {
        const char* s_path = nullptr;
        sd_bus_message_read(reply.raw(), "o", &s_path);

        const void* p_data = nullptr;
        size_t p_size = 0;
        sd_bus_message_read_array(reply.raw(), 'y', &p_data, &p_size);

        const void* v_data = nullptr;
        size_t v_size = 0;
        sd_bus_message_read_array(reply.raw(), 'y', &v_data, &v_size);

        if (v_data && v_size > 0) {
            out_secret_value.assign(reinterpret_cast<const char*>(v_data), v_size);
        } else {
            out_secret_value.clear();
        }

        reply.exit_container();
        return true;
    }

    return false;
}

bool BusConnection::secret_service_get_item_attributes(const std::string& item_path,
                                                       std::map<std::string, std::string>& out_attrs,
                                                       std::string* error) {
    if (!bus_.is_valid()) return false;

    brodbus::Message m = bus_.new_method_call(
        "org.freedesktop.secrets",
        item_path,
        "org.freedesktop.DBus.Properties",
        "Get");
    if (!m) return false;

    m.append_string("org.freedesktop.Secret.Item");
    m.append_string("Attributes");

    brodbus::Error err;
    brodbus::Message reply = bus_.call(m, 0, &err);
    if (!reply) {
        record_error(err, "Get Attributes failed", error);
        return false;
    }

    out_attrs.clear();
    // Variant containing a{ss}
    if (reply.enter_container('v', "a{ss}") > 0) {
        if (reply.enter_container('a', "{ss}") > 0) {
            const char* k = nullptr;
            const char* v = nullptr;
            while (sd_bus_message_read(reply.raw(), "{ss}", &k, &v) > 0 && k && v) {
                out_attrs[k] = v;
            }
            reply.exit_container();
        }
        reply.exit_container();
        return true;
    }

    return false;
}

bool BusConnection::secret_service_delete_item(const std::string& item_path, std::string* error) {
    if (!bus_.is_valid()) return false;

    brodbus::Message m = bus_.new_method_call(
        "org.freedesktop.secrets",
        item_path,
        "org.freedesktop.Secret.Item",
        "Delete");
    if (!m) return false;

    brodbus::Error err;
    brodbus::Message reply = bus_.call(m, 0, &err);
    if (!reply) {
        record_error(err, "DeleteItem failed", error);
        return false;
    }

    return true;
}

bool BusConnection::fprint_get_devices(std::vector<std::string>& out_devices, std::string* error) {
    if (!bus_.is_valid()) return false;

    brodbus::Message m = bus_.new_method_call(
        "net.reactivated.Fprint",
        "/net/reactivated/Fprint/Manager",
        "net.reactivated.Fprint.Manager",
        "GetDevices");
    if (!m) return false;

    brodbus::Error err;
    brodbus::Message reply = bus_.call(m, 0, &err);
    if (!reply) {
        record_error(err, "fprint GetDevices failed", error);
        return false;
    }

    out_devices.clear();
    if (reply.enter_container('a', "o") > 0) {
        const char* path = nullptr;
        while (sd_bus_message_read(reply.raw(), "o", &path) > 0 && path) {
            out_devices.push_back(path);
        }
        reply.exit_container();
    }

    return true;
}

bool BusConnection::fprint_list_enrolled_fingers(const std::string& device_path,
                                                 const std::string& username,
                                                 std::vector<std::string>& out_fingers,
                                                 std::string* error) {
    if (!bus_.is_valid()) return false;

    brodbus::Message m = bus_.new_method_call(
        "net.reactivated.Fprint",
        device_path,
        "net.reactivated.Fprint.Device",
        "ListEnrolledFingers");
    if (!m) return false;

    m.append_string(username);

    brodbus::Error err;
    brodbus::Message reply = bus_.call(m, 0, &err);
    if (!reply) {
        record_error(err, "fprint ListEnrolledFingers failed", error);
        return false;
    }

    out_fingers.clear();
    if (reply.enter_container('a', "s") > 0) {
        const char* finger = nullptr;
        while (sd_bus_message_read(reply.raw(), "s", &finger) > 0 && finger) {
            out_fingers.push_back(finger);
        }
        reply.exit_container();
    }

    return true;
}

}  // namespace brocred::linux_dbus
