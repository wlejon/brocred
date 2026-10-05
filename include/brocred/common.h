// Core status and enum types for brocred.
#pragma once

#include <cstdint>
#include <string>
#include <utility>

namespace brocred {

// Outcome of an operation. error is empty on success.
struct Result {
    bool ok = false;
    std::string error;

    explicit operator bool() const noexcept { return ok; }
    static Result success() { return Result{true, std::string()}; }
    static Result failure(std::string why) { return Result{false, std::move(why)}; }
};

// General availability state for system capabilities or privileges.
enum class Availability {
    Unknown,
    No,
    Yes,
    NeedsAuth,
};

const char* to_string(Availability a);

// Specific availability state for biometric authentication.
enum class BiometricAvailability {
    Unknown,
    NotAvailable,
    NotConfigured,
    Available,
    DisabledByPolicy,
};

const char* to_string(BiometricAvailability a);

// Modality of biometric authentication supported by the hardware.
enum class BiometricType {
    None,
    Fingerprint,
    Face,
    Iris,
    Multiple,
};

const char* to_string(BiometricType t);

}  // namespace brocred

#include <ostream>

namespace brocred {

inline std::ostream& operator<<(std::ostream& os, Availability a) {
    return os << to_string(a);
}

inline std::ostream& operator<<(std::ostream& os, BiometricAvailability a) {
    return os << to_string(a);
}

inline std::ostream& operator<<(std::ostream& os, BiometricType t) {
    return os << to_string(t);
}

}  // namespace brocred
