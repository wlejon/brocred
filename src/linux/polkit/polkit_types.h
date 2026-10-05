// D-Bus serializers and utility functions for PolicyKit types.
#pragma once

#include "brocred/polkit_agent.h"

#include <systemd/sd-bus.h>

#include <vector>

namespace brocred::polkit {

// Subject helpers
int append_subject(sd_bus_message* m, const PolkitSubject& subject);
int read_subject(sd_bus_message* m, PolkitSubject& subject);

// Identity helpers
int append_identity(sd_bus_message* m, const PolkitIdentity& identity);
int read_identity(sd_bus_message* m, PolkitIdentity& identity);

// Identity list helpers
int append_identities(sd_bus_message* m, const std::vector<PolkitIdentity>& identities);
int read_identities(sd_bus_message* m, std::vector<PolkitIdentity>& identities);

// Details dictionary helpers
int append_details(sd_bus_message* m, const std::map<std::string, std::string>& details);
int read_details(sd_bus_message* m, std::map<std::string, std::string>& details);

// System process start-time lookup from /proc/self/stat
uint64_t read_process_start_time(uint32_t pid);

}  // namespace brocred::polkit
