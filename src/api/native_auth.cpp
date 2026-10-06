#include "host_cred_internal.h"
#include "brocred/verifier.h"

#include <deque>
#include <mutex>

namespace brocred::api {

namespace {

struct PendingAuth {
    uint64_t reqId{0};
    ev::Persistent promise;
};

std::mutex g_authMu;
std::vector<PendingAuth> g_pendingAuth;
std::vector<brocred::AuthPromptEvent> g_queuedAuthEvents;

} // namespace

void handleAuthEvent(const brocred::AuthPromptEvent& evItem) {
    std::lock_guard lock(g_authMu);
    g_queuedAuthEvents.push_back(evItem);
}

void drainAuth() {
    std::vector<brocred::AuthPromptEvent> events;
    {
        std::lock_guard lock(g_authMu);
        events.swap(g_queuedAuthEvents);
    }

    if (events.empty()) return;

    for (const auto& evItem : events) {
        ev::Persistent matchedPromise;
        {
            std::lock_guard lock(g_authMu);
            for (auto it = g_pendingAuth.begin(); it != g_pendingAuth.end(); ++it) {
                if (it->reqId == evItem.request_id) {
                    matchedPromise.set(it->promise.get());
                    g_pendingAuth.erase(it);
                    break;
                }
            }
        }
        if (!matchedPromise.get().isUndefined()) {
            ev::resolvePromise(matchedPromise.get(), ev::fromBool(evItem.success));
        }
    }
}

void shutdownAuth() {
    std::vector<PendingAuth> pending;
    {
        std::lock_guard lock(g_authMu);
        pending.swap(g_pendingAuth);
        g_queuedAuthEvents.clear();
    }
    for (auto& p : pending) {
        ev::Persistent err(makeError("Authentication cancelled"));
        ev::rejectPromise(p.promise.get(), err.get());
    }
}

void installAuthOnto(Value credObj) {
    ObjectBuilder cred(credObj);

    // bro.cred.authenticate(username, password) -> Promise<boolean>
    // bro.cred.authenticate(password) -> Promise<boolean>
    auto authFn = [](Value, std::span<const Value> args) -> Value {
        ev::Persistent arg0(args.size() > 0 ? args[0] : ev::undefined());
        ev::Persistent arg1(args.size() > 1 ? args[1] : ev::undefined());

        ev::Persistent promise(ev::createPromise());

        if (args.empty()) {
            ev::Persistent err(makeError("authenticate requires at least 1 argument"));
            ev::rejectPromise(promise.get(), err.get());
            return promise.get();
        }

        std::string username;
        std::string password;
        if (args.size() == 1) {
            password = ev::toUtf8(arg0.get());
        } else {
            username = ev::toUtf8(arg0.get());
            password = ev::toUtf8(arg1.get());
        }

        uint64_t reqId = brocred::verify_password_async(credEventQueue(), username, password);
        {
            std::lock_guard lock(g_authMu);
            PendingAuth p;
            p.reqId = reqId;
            p.promise.set(promise.get());
            g_pendingAuth.push_back(std::move(p));
        }

        return promise.get();
    };

    cred.def("authenticate", 1, authFn);
    cred.def("verifyPassword", 1, authFn);

    // bro.cred.authenticateSync(username, password) -> boolean
    auto authSyncFn = [](Value, std::span<const Value> args) -> Value {
        ev::Persistent arg0(args.size() > 0 ? args[0] : ev::undefined());
        ev::Persistent arg1(args.size() > 1 ? args[1] : ev::undefined());

        if (args.empty()) {
            return ev::throwTypeError("authenticateSync requires at least 1 argument");
        }

        std::string username;
        std::string password;
        if (args.size() == 1) {
            password = ev::toUtf8(arg0.get());
        } else {
            username = ev::toUtf8(arg0.get());
            password = ev::toUtf8(arg1.get());
        }

        brocred::VerifyResult res = username.empty()
            ? brocred::verify_password(password)
            : brocred::verify_password(username, password);

        return ev::fromBool(res.success);
    };

    cred.def("authenticateSync", 1, authSyncFn);
    cred.def("verifyPasswordSync", 1, authSyncFn);
}

} // namespace brocred::api
