// Internal implementation of PolicyKit Authentication Agent.
#pragma once

#include "brocred/polkit_agent.h"
#include "linux/polkit/polkit_types.h"

#include <systemd/sd-bus.h>

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace brocred::polkit {

struct ActiveAuthSession {
    std::string cookie;
    bool cancelled = false;
};

class PolkitAgentImpl : public PolkitAgent {
public:
    PolkitAgentImpl(PolkitAgentOptions options, PolkitAuthHandler handler);
    ~PolkitAgentImpl() override;

    Result start() override;
    void stop() override;
    bool is_running() const override { return running_.load(); }

    Result register_with_authority() override;
    Result unregister_with_authority() override;
    bool is_registered() const override { return is_registered_.load(); }

    bool process_one(uint64_t timeout_usec = 0) override;

    PolkitAuthResponse handle_begin_authentication(const PolkitAuthRequest& request) override;
    void handle_cancel_authentication(const std::string& cookie) override;
    bool has_active_session(const std::string& cookie) const override;

    // D-Bus method trampolines
    int dbus_begin_authentication(sd_bus_message* m, sd_bus_error* ret_error);
    int dbus_cancel_authentication(sd_bus_message* m, sd_bus_error* ret_error);

private:
    Result init_bus();
    void run_worker();
    void send_authority_response(const std::string& cookie, const PolkitIdentity& identity);

    PolkitAgentOptions options_;
    PolkitAuthHandler handler_;

    sd_bus* bus_ = nullptr;
    sd_bus* authority_bus_ = nullptr;
    sd_bus_slot* slot_ = nullptr;

    std::atomic<bool> running_{false};
    std::atomic<bool> is_registered_{false};
    std::thread worker_thread_;

    mutable std::mutex mutex_;
    std::map<std::string, ActiveAuthSession> active_sessions_;
};

}  // namespace brocred::polkit
