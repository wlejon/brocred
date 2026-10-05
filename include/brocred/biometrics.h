// Biometric hardware availability and capabilities query API.
#pragma once

#include "brocred/common.h"
#include "brocred/events.h"

#include <string>

namespace brocred {

struct BiometricCapabilities {
    bool supported = false;
    BiometricAvailability availability = BiometricAvailability::Unknown;
    BiometricType primary_type = BiometricType::None;
    bool has_fingerprint = false;
    bool has_face = false;
    bool has_iris = false;
    std::string sensor_name;
    std::string details;

    bool operator==(const BiometricCapabilities& other) const = default;
};

// Queries and reports real biometric capabilities honestly for the current platform.
// (Windows: Windows Hello / WinBio, macOS: LocalAuthentication / LAContext, Linux: fprintd).
BiometricCapabilities get_biometric_capabilities();

// Asynchronously inspects biometric state and posts BiometricStatusEvent to the queue.
void check_biometrics_async(EventQueue& queue);

}  // namespace brocred
