#include "brocred/biometrics.h"
#if defined(BROCRED_HAVE_SDBUS)
#include "linux/dbus/dbus_bus.h"
#else
#include "linux/dbus/dbus_unavailable.h"
#endif

#include <pwd.h>
#include <unistd.h>
#include <cstdlib>

namespace brocred {

#if defined(BROCRED_HAVE_SDBUS)
namespace {

std::string get_current_user() {
    const char* user = getlogin();
    if (user && *user) return user;
    struct passwd* pw = getpwuid(getuid());
    if (pw && pw->pw_name) return pw->pw_name;
    const char* uenv = std::getenv("USER");
    if (uenv && *uenv) return uenv;
    return "";
}

}  // namespace
#endif

BiometricCapabilities get_biometric_capabilities() {
    BiometricCapabilities caps;
    caps.supported = false;
    caps.availability = BiometricAvailability::NotAvailable;
    caps.primary_type = BiometricType::None;

#if !defined(BROCRED_HAVE_SDBUS)
    // fprintd is only reachable over D-Bus; without it the state is unknown,
    // not absent.
    caps.availability = BiometricAvailability::Unknown;
    caps.details = std::string("Cannot query fprintd: ") + linux_dbus::kNoSdBus;
    return caps;
#else

    auto bus = linux_dbus::BusConnection::open(linux_dbus::BusType::System);
    if (!bus || !bus->valid()) {
        caps.details = "System D-Bus unavailable for fprintd check";
        return caps;
    }

    std::vector<std::string> devices;
    std::string err;
    if (!bus->fprint_get_devices(devices, &err) || devices.empty()) {
        caps.details = devices.empty() ? "No fingerprint devices found by fprintd" : err;
        return caps;
    }

    caps.supported = true;
    caps.has_fingerprint = true;
    caps.primary_type = BiometricType::Fingerprint;
    caps.sensor_name = devices[0];

    std::string user = get_current_user();
    std::vector<std::string> enrolled;
    if (!user.empty() && bus->fprint_list_enrolled_fingers(devices[0], user, enrolled, &err)) {
        if (!enrolled.empty()) {
            caps.availability = BiometricAvailability::Available;
            caps.details = "Fingerprint enrolled and ready (" + std::to_string(enrolled.size()) + " fingers)";
        } else {
            caps.availability = BiometricAvailability::NotConfigured;
            caps.details = "Fingerprint hardware present but no fingers enrolled for user " + user;
        }
    } else {
        caps.availability = BiometricAvailability::NotConfigured;
        caps.details = "Fingerprint device present (unable to verify enrollments: " + err + ")";
    }

    return caps;
#endif
}

}  // namespace brocred
