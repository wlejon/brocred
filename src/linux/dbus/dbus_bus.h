// Minimal sd-bus client helper for brocred on Linux.
#pragma once

#include "brodbus/bus.h"
#include "brodbus/error.h"

#include <chrono>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace brocred::linux_dbus {

enum class BusType {
    User,
    System,
    Address,
};

class BusConnection {
public:
    static std::unique_ptr<BusConnection> open(BusType type, const std::string& address = "");
    explicit BusConnection(brodbus::Bus bus);
    explicit BusConnection(sd_bus* bus);
    ~BusConnection();

    bool valid() const { return bus_.is_valid(); }
    sd_bus* get() const { return bus_.raw(); }
    brodbus::Bus& bus() { return bus_; }
    const brodbus::Bus& bus() const { return bus_; }

    // Returns true if a bus name is currently owned or activatable.
    bool has_owner(const std::string& name);

    // Freedesktop Secret Service calls
    bool secret_service_open_session(std::string& out_session_path, std::string* error = nullptr);

    bool secret_service_create_item(const std::string& collection_path,
                                    const std::string& session_path,
                                    const std::string& label,
                                    const std::map<std::string, std::string>& attributes,
                                    const std::string& secret_value,
                                    bool replace,
                                    std::string& out_item_path,
                                    std::string* error = nullptr);

    bool secret_service_search_items(const std::map<std::string, std::string>& attributes,
                                     std::vector<std::string>& out_unlocked,
                                     std::vector<std::string>& out_locked,
                                     std::string* error = nullptr);

    bool secret_service_unlock(const std::vector<std::string>& locked_paths,
                               std::vector<std::string>& out_unlocked,
                               std::string* error = nullptr);

    bool secret_service_get_secret(const std::string& item_path,
                                   const std::string& session_path,
                                   std::string& out_secret_value,
                                   std::string* error = nullptr);

    bool secret_service_get_item_attributes(const std::string& item_path,
                                            std::map<std::string, std::string>& out_attrs,
                                            std::string* error = nullptr);

    bool secret_service_delete_item(const std::string& item_path, std::string* error = nullptr);

    // fprintd calls on system bus
    bool fprint_get_devices(std::vector<std::string>& out_devices, std::string* error = nullptr);
    bool fprint_list_enrolled_fingers(const std::string& device_path,
                                      const std::string& username,
                                      std::vector<std::string>& out_fingers,
                                      std::string* error = nullptr);

private:
    brodbus::Bus bus_;
};

}  // namespace brocred::linux_dbus
