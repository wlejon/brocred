// Stand-in for BusConnection in builds without sd-bus (libsystemd).
//
// open() always fails, so callers take their documented no-D-Bus paths: the
// credential store uses the file keystore and reports "FileKeystore", and
// BackendType::System fails with an explanation. Nothing here pretends to be
// a Secret Service; the methods exist only so the callers compile unchanged.
#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace brocred::linux_dbus {

inline constexpr const char* kNoSdBus =
    "brocred was built without sd-bus (libsystemd), so D-Bus services are unavailable";

enum class BusType {
    User,
    System,
    Address,
};

class BusConnection {
public:
    static std::unique_ptr<BusConnection> open(BusType, const std::string& = "") { return nullptr; }

    bool valid() const { return false; }
    bool has_owner(const std::string&) { return false; }

    bool secret_service_open_session(std::string&, std::string* error = nullptr) { return fail(error); }
    bool secret_service_create_item(const std::string&, const std::string&, const std::string&,
                                    const std::map<std::string, std::string>&, const std::string&, bool,
                                    std::string&, std::string* error = nullptr) {
        return fail(error);
    }
    bool secret_service_search_items(const std::map<std::string, std::string>&, std::vector<std::string>&,
                                     std::vector<std::string>&, std::string* error = nullptr) {
        return fail(error);
    }
    bool secret_service_unlock(const std::vector<std::string>&, std::vector<std::string>&,
                               std::string* error = nullptr) {
        return fail(error);
    }
    bool secret_service_get_secret(const std::string&, const std::string&, std::string&,
                                   std::string* error = nullptr) {
        return fail(error);
    }
    bool secret_service_get_item_attributes(const std::string&, std::map<std::string, std::string>&,
                                            std::string* error = nullptr) {
        return fail(error);
    }
    bool secret_service_delete_item(const std::string&, std::string* error = nullptr) { return fail(error); }

private:
    static bool fail(std::string* error) {
        if (error) *error = kNoSdBus;
        return false;
    }
};

}  // namespace brocred::linux_dbus
