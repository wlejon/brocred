// Snapshot events posted by brocred backends.
#pragma once

#include "brocred/common.h"
#include "brocred/event_queue.h"

#include <cstdint>
#include <string>
#include <variant>

namespace brocred {

// Notifies that a credential was stored or deleted.
struct CredentialChangedEvent {
    enum class ChangeType {
        Stored,
        Deleted,
    };

    ChangeType change = ChangeType::Stored;
    std::string service;
    std::string account;

    bool operator==(const CredentialChangedEvent& other) const = default;
};

// Result of an asynchronous authentication verification or prompt.
struct AuthPromptEvent {
    uint64_t request_id = 0;
    bool success = false;
    std::string error;

    bool operator==(const AuthPromptEvent& other) const = default;
};

// State change notification for biometric hardware.
struct BiometricStatusEvent {
    BiometricAvailability availability = BiometricAvailability::Unknown;
    std::string details;

    bool operator==(const BiometricStatusEvent& other) const = default;
};

using Event = std::variant<CredentialChangedEvent, AuthPromptEvent, BiometricStatusEvent>;
using EventQueue = MessageQueue<Event>;

}  // namespace brocred
