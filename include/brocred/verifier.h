// Lock screen password verification API.
#pragma once

#include "brocred/events.h"

#include <cstdint>
#include <string>

namespace brocred {

struct VerifyResult {
    bool success = false;
    std::string error;

    explicit operator bool() const noexcept { return success; }
};

// Verifies password for current logged-in user against system auth
// (Windows: LogonUserW, Linux: PAM, macOS: OpenDirectory).
VerifyResult verify_password(const std::string& password);

// Verifies password for a specific user.
VerifyResult verify_password(const std::string& username, const std::string& password);

// Verifies password for a user within a domain (Windows) or custom PAM service (Linux).
VerifyResult verify_password(const std::string& username, const std::string& domain_or_service,
                             const std::string& password);

// Asynchronously verifies password and pushes an AuthPromptEvent to the provided queue.
// Returns a unique request ID.
uint64_t verify_password_async(EventQueue& queue, const std::string& username,
                               const std::string& password);

}  // namespace brocred
