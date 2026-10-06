// Private isolated dbus-daemon for real wire-protocol D-Bus tests.
#pragma once

#include "brodbus/private_bus.h"

#include <string>
#include <sys/types.h>

namespace brocred::test {

class PrivateBus {
public:
    PrivateBus() = default;
    ~PrivateBus() = default;

    PrivateBus(const PrivateBus&) = delete;
    PrivateBus& operator=(const PrivateBus&) = delete;

    PrivateBus(PrivateBus&&) noexcept = default;
    PrivateBus& operator=(PrivateBus&&) noexcept = default;

    bool ok() const { return bus_.ok(); }
    const std::string& address() const { return bus_.address(); }
    pid_t pid() const { return bus_.pid(); }
    void stop() { bus_.stop(); }

    const brodbus::PrivateBus& raw() const { return bus_; }
    brodbus::PrivateBus& raw() { return bus_; }

private:
    brodbus::PrivateBus bus_;
};

}  // namespace brocred::test
