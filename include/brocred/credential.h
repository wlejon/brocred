// Data structures representing secrets and credential metadata.
#pragma once

#include <chrono>
#include <map>
#include <string>

namespace brocred {

// Stored secret payload with service, account, and optional key-value attributes.
struct Credential {
    std::string service;
    std::string account;
    std::string secret;
    std::map<std::string, std::string> attributes;

    bool operator==(const Credential& other) const = default;
};

// Summary metadata of a stored credential (omits secret text).
struct CredentialMetadata {
    std::string service;
    std::string account;
    std::map<std::string, std::string> attributes;
    std::chrono::system_clock::time_point last_modified{};

    bool operator==(const CredentialMetadata& other) const = default;
};

}  // namespace brocred
