// Implementation of PolicyKit Authentication Agent D-Bus export and authority interaction.
#include "linux/polkit/polkit_agent_impl.h"
#include "linux/polkit/polkit_conversation.h"

#include <clocale>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

namespace brocred::polkit {

namespace {

int dbus_agent_begin_auth(sd_bus_message* m, void* userdata, sd_bus_error* ret_error) {
    return static_cast<PolkitAgentImpl*>(userdata)->dbus_begin_authentication(m, ret_error);
}

int dbus_agent_cancel_auth(sd_bus_message* m, void* userdata, sd_bus_error* ret_error) {
    return static_cast<PolkitAgentImpl*>(userdata)->dbus_cancel_authentication(m, ret_error);
}

const sd_bus_vtable kAuthAgentVtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("BeginAuthentication", "sssa{ss}sa(sa{sv})", "", dbus_agent_begin_auth, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("CancelAuthentication", "s", "", dbus_agent_cancel_auth, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_VTABLE_END
};

std::string get_default_locale() {
    const char* loc = std::setlocale(LC_ALL, nullptr);
    if (loc && *loc && std::strcmp(loc, "C") != 0) return loc;
    const char* lang = std::getenv("LANG");
    if (lang && *lang) return lang;
    return "en_US.UTF-8";
}

}  // namespace

PolkitAgentImpl::PolkitAgentImpl(PolkitAgentOptions options, PolkitAuthHandler handler)
    : options_(std::move(options)), handler_(std::move(handler)) {
    if (options_.locale.empty()) {
        options_.locale = get_default_locale();
    }
}

PolkitAgentImpl::~PolkitAgentImpl() {
    stop();
    if (is_registered_.load()) {
        unregister_with_authority();
    }
    if (slot_) {
        sd_bus_slot_unref(slot_);
        slot_ = nullptr;
    }
    if (bus_) {
        sd_bus_flush_close_unref(bus_);
        bus_ = nullptr;
    }
    if (authority_bus_) {
        sd_bus_flush_close_unref(authority_bus_);
        authority_bus_ = nullptr;
    }
}

Result PolkitAgentImpl::init_bus() {
    if (bus_) return Result::success();

    int r = 0;
    if (!options_.bus_address.empty()) {
        r = sd_bus_new(&bus_);
        if (r >= 0) r = sd_bus_set_address(bus_, options_.bus_address.c_str());
        if (r >= 0) r = sd_bus_set_bus_client(bus_, 1);
        if (r >= 0) r = sd_bus_start(bus_);
    } else {
        r = sd_bus_open_user(&bus_);
    }

    if (r < 0 || !bus_) {
        return Result::failure("Failed to connect to D-Bus for Polkit agent: " + std::string(strerror(-r)));
    }

    r = sd_bus_add_object_vtable(bus_, &slot_,
                                 options_.object_path.c_str(),
                                 "org.freedesktop.PolicyKit1.AuthenticationAgent",
                                 kAuthAgentVtable, this);
    if (r < 0) {
        return Result::failure("Failed to export AuthenticationAgent vtable: " + std::string(strerror(-r)));
    }

    const char* uniq = nullptr;
    sd_bus_get_unique_name(bus_, &uniq);

    return Result::success();
}

Result PolkitAgentImpl::start() {
    if (running_.load()) return Result::success();

    Result r = init_bus();
    if (!r.ok) return r;

    if (options_.register_with_authority) {
        register_with_authority();
    }

    running_ = true;
    worker_thread_ = std::thread(&PolkitAgentImpl::run_worker, this);
    return Result::success();
}

void PolkitAgentImpl::stop() {
    if (!running_.exchange(false)) return;
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

bool PolkitAgentImpl::process_one(uint64_t timeout_usec) {
    if (!bus_) {
        Result r = init_bus();
        if (!r.ok) return false;
    }
    int r = sd_bus_process(bus_, nullptr);
    if (r > 0) return true;
    r = sd_bus_wait(bus_, timeout_usec);
    if (r < 0) return false;
    return sd_bus_process(bus_, nullptr) > 0;
}

void PolkitAgentImpl::run_worker() {
    while (running_.load()) {
        int r = sd_bus_process(bus_, nullptr);
        if (r > 0) continue;
        sd_bus_wait(bus_, 20000);
    }
}

Result PolkitAgentImpl::register_with_authority() {
    if (is_registered_.load()) return Result::success();

    if (!authority_bus_) {
        int r = 0;
        if (!options_.bus_address.empty()) {
            r = sd_bus_new(&authority_bus_);
            if (r >= 0) r = sd_bus_set_address(authority_bus_, options_.bus_address.c_str());
            if (r >= 0) r = sd_bus_set_bus_client(authority_bus_, 1);
            if (r >= 0) r = sd_bus_start(authority_bus_);
        } else {
            r = sd_bus_open_system(&authority_bus_);
        }
        if (r < 0 || !authority_bus_) {
            return Result::failure("Cannot open system bus for PolicyKit Authority: " + std::string(strerror(-r)));
        }
    }

    sd_bus_message* m = nullptr;
    int r = sd_bus_message_new_method_call(authority_bus_, &m,
                                           "org.freedesktop.PolicyKit1",
                                           "/org/freedesktop/PolicyKit1/Authority",
                                           "org.freedesktop.PolicyKit1.Authority",
                                           "RegisterAuthenticationAgent");
    if (r < 0) {
        return Result::failure("Failed to construct RegisterAuthenticationAgent message");
    }

    // Subject (sa{sv})
    r = append_subject(m, options_.subject);
    if (r >= 0) {
        // locale (s)
        sd_bus_message_append(m, "s", options_.locale.c_str());
        // object_path (s)
        sd_bus_message_append(m, "s", options_.object_path.c_str());
    }

    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message* reply = nullptr;
    r = sd_bus_call(authority_bus_, m, 0, &err, &reply);
    sd_bus_message_unref(m);

    if (r < 0) {
        std::string err_msg = err.message ? err.message : strerror(-r);
        sd_bus_error_free(&err);
        return Result::failure("RegisterAuthenticationAgent failed: " + err_msg);
    }

    sd_bus_message_unref(reply);
    sd_bus_error_free(&err);
    is_registered_ = true;
    return Result::success();
}

Result PolkitAgentImpl::unregister_with_authority() {
    if (!is_registered_.load() || !authority_bus_) return Result::success();

    sd_bus_message* m = nullptr;
    int r = sd_bus_message_new_method_call(authority_bus_, &m,
                                           "org.freedesktop.PolicyKit1",
                                           "/org/freedesktop/PolicyKit1/Authority",
                                           "org.freedesktop.PolicyKit1.Authority",
                                           "UnregisterAuthenticationAgent");
    if (r >= 0) {
        append_subject(m, options_.subject);
        sd_bus_message_append(m, "s", options_.object_path.c_str());
        sd_bus_call(authority_bus_, m, 0, nullptr, nullptr);
        sd_bus_message_unref(m);
    }

    is_registered_ = false;
    return Result::success();
}

void PolkitAgentImpl::send_authority_response(const std::string& cookie, const PolkitIdentity& identity) {
    if (!authority_bus_) return;

    sd_bus_message* m = nullptr;
    // Prefer AuthenticationAgentResponse2 (takes uid, cookie, identity)
    int r = sd_bus_message_new_method_call(authority_bus_, &m,
                                           "org.freedesktop.PolicyKit1",
                                           "/org/freedesktop/PolicyKit1/Authority",
                                           "org.freedesktop.PolicyKit1.Authority",
                                           "AuthenticationAgentResponse2");
    if (r >= 0) {
        sd_bus_message_append(m, "u", static_cast<uint32_t>(getuid()));
        sd_bus_message_append(m, "s", cookie.c_str());
        append_identity(m, identity);
        sd_bus_call(authority_bus_, m, 0, nullptr, nullptr);
        sd_bus_message_unref(m);
    }
}

PolkitAuthResponse PolkitAgentImpl::handle_begin_authentication(const PolkitAuthRequest& request) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = active_sessions_.find(request.cookie);
        if (it != active_sessions_.end() && it->second.cancelled) {
            return PolkitAuthResponse::cancel("Authentication cancelled before execution");
        }
        active_sessions_[request.cookie] = ActiveAuthSession{request.cookie, false};
    }

    PolkitAuthResponse resp;
    if (handler_) {
        resp = handler_(request);
    } else {
        resp = default_conversation_handler(request, options_.fallback_password);
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = active_sessions_.find(request.cookie);
        if (it != active_sessions_.end() && it->second.cancelled) {
            active_sessions_.erase(it);
            return PolkitAuthResponse::cancel("Authentication was cancelled");
        }
        active_sessions_.erase(request.cookie);
    }

    return resp;
}

void PolkitAgentImpl::handle_cancel_authentication(const std::string& cookie) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = active_sessions_.find(cookie);
    if (it != active_sessions_.end()) {
        it->second.cancelled = true;
    } else {
        active_sessions_[cookie] = ActiveAuthSession{cookie, true};
    }
}

bool PolkitAgentImpl::has_active_session(const std::string& cookie) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = active_sessions_.find(cookie);
    return it != active_sessions_.end() && !it->second.cancelled;
}

int PolkitAgentImpl::dbus_begin_authentication(sd_bus_message* m, sd_bus_error* ret_error) {
    PolkitAuthRequest req;
    const char *action = nullptr, *msg = nullptr, *icon = nullptr, *cookie = nullptr;
    int r = sd_bus_message_read(m, "sss", &action, &msg, &icon);
    if (r < 0) return r;
    if (action) req.action_id = action;
    if (msg) req.message = msg;
    if (icon) req.icon_name = icon;

    r = read_details(m, req.details);
    if (r < 0) return r;

    r = sd_bus_message_read(m, "s", &cookie);
    if (r < 0) return r;
    if (cookie) req.cookie = cookie;

    r = read_identities(m, req.identities);
    if (r < 0) return r;

    PolkitAuthResponse resp = handle_begin_authentication(req);

    if (resp.cancelled) {
        return sd_bus_error_setf(ret_error, "org.freedesktop.PolicyKit1.Error.Cancelled",
                                 "%s", resp.error_message.empty() ? "Authentication cancelled" : resp.error_message.c_str());
    }

    if (!resp.success) {
        return sd_bus_error_setf(ret_error, "org.freedesktop.PolicyKit1.Error.Failed",
                                 "%s", resp.error_message.empty() ? "Authentication failed" : resp.error_message.c_str());
    }

    if (is_registered_.load()) {
        send_authority_response(req.cookie, resp.authenticated_identity);
    }

    return sd_bus_reply_method_return(m, "");
}

int PolkitAgentImpl::dbus_cancel_authentication(sd_bus_message* m, sd_bus_error* /*ret_error*/) {
    const char* cookie = nullptr;
    sd_bus_message_read(m, "s", &cookie);
    if (cookie) {
        handle_cancel_authentication(cookie);
    }
    return sd_bus_reply_method_return(m, "");
}

}  // namespace brocred::polkit
