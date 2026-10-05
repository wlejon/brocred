// Public interface for PolicyKit Authentication Agent (org.freedesktop.PolicyKit1.AuthenticationAgent).
#pragma once

#include "brocred/common.h"

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace brocred {

struct PolkitSubject {
    enum class Kind {
        UnixProcess,
        UnixSession,
    };
    Kind kind = Kind::UnixProcess;
    uint32_t pid = 0;
    uint64_t start_time = 0;
    std::string session_id;

    static PolkitSubject current_process();
    static PolkitSubject process(uint32_t pid, uint64_t start_time = 0);
    static PolkitSubject session(std::string session_id);
};

struct PolkitIdentity {
    enum class Kind {
        UnixUser,
        UnixGroup,
    };
    Kind kind = Kind::UnixUser;
    uint32_t id = 0;    // uid or gid
    std::string name;  // username or group name

    static PolkitIdentity user(uint32_t uid, std::string name = "");
    static PolkitIdentity group(uint32_t gid, std::string name = "");
    static PolkitIdentity current_user();
};

struct PolkitAuthRequest {
    std::string action_id;
    std::string message;
    std::string icon_name;
    std::map<std::string, std::string> details;
    std::string cookie;
    std::vector<PolkitIdentity> identities;
};

struct PolkitAuthResponse {
    bool success = false;
    bool cancelled = false;
    PolkitIdentity authenticated_identity;
    std::string error_message;

    static PolkitAuthResponse ok(PolkitIdentity identity) {
        return PolkitAuthResponse{true, false, std::move(identity), ""};
    }
    static PolkitAuthResponse cancel(std::string msg = "Cancelled by user") {
        return PolkitAuthResponse{false, true, {}, std::move(msg)};
    }
    static PolkitAuthResponse fail(std::string why) {
        return PolkitAuthResponse{false, false, {}, std::move(why)};
    }
};

using PolkitAuthHandler = std::function<PolkitAuthResponse(const PolkitAuthRequest& request)>;

struct PolkitAgentOptions {
    std::string object_path = "/org/freedesktop/PolicyKit1/AuthenticationAgent";
    std::string locale;  // empty defaults to LC_ALL / LANG or "en_US.UTF-8"
    PolkitSubject subject = PolkitSubject::current_process();
    bool register_with_authority = false;  // set true to register with PolicyKit Authority
    std::string bus_address;              // empty = standard bus
    std::string fallback_password;        // optional password for automated verification
};

class PolkitAgent {
public:
    static std::unique_ptr<PolkitAgent> create(
        const PolkitAgentOptions& options = {},
        PolkitAuthHandler handler = nullptr);

    virtual ~PolkitAgent() = default;

    // Start background event loop thread
    virtual Result start() = 0;
    // Stop background event loop
    virtual void stop() = 0;
    // Check if running
    virtual bool is_running() const = 0;

    // Register / Unregister with PolicyKit Authority
    virtual Result register_with_authority() = 0;
    virtual Result unregister_with_authority() = 0;
    virtual bool is_registered() const = 0;

    // Process a single D-Bus event iteration (useful for tests or custom loops)
    virtual bool process_one(uint64_t timeout_usec = 0) = 0;

    // Direct dispatch for authentication request
    virtual PolkitAuthResponse handle_begin_authentication(const PolkitAuthRequest& request) = 0;
    // Direct dispatch for cancellation
    virtual void handle_cancel_authentication(const std::string& cookie) = 0;

    // Check if an authentication session is currently active for cookie
    virtual bool has_active_session(const std::string& cookie) const = 0;
};

}  // namespace brocred
