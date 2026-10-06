#include "host_cred_internal.h"
#include "brocred/polkit_agent.h"

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <vector>

namespace brocred::api {

namespace {

struct PolkitQueuedRequest {
    uint64_t id{0};
    brocred::PolkitAuthRequest request;
    std::mutex mu;
    std::condition_variable cv;
    bool answered = false;
    brocred::PolkitAuthResponse response;
};

std::mutex g_polkitMu;
std::unique_ptr<brocred::PolkitAgent> g_polkitAgent;
std::unique_ptr<ev::Persistent> g_polkitCallback;
uint64_t g_nextPolkitReqId = 1;
std::vector<std::shared_ptr<PolkitQueuedRequest>> g_activePolkitRequests;
std::vector<std::shared_ptr<PolkitQueuedRequest>> g_unhandledPolkitRequests;

brocred::PolkitAuthResponse handleIncomingPolkitRequest(const brocred::PolkitAuthRequest& req) {
    auto qReq = std::make_shared<PolkitQueuedRequest>();
    qReq->request = req;

    {
        std::lock_guard lock(g_polkitMu);
        qReq->id = ++g_nextPolkitReqId;
        if (!g_polkitCallback) {
            return brocred::PolkitAuthResponse::fail("No PolicyKit agent callback registered");
        }
        g_activePolkitRequests.push_back(qReq);
        g_unhandledPolkitRequests.push_back(qReq);
    }

    std::unique_lock ulock(qReq->mu);
    bool ok = qReq->cv.wait_for(ulock, std::chrono::seconds(30), [&]() {
        return qReq->answered;
    });

    {
        std::lock_guard lock(g_polkitMu);
        for (auto it = g_activePolkitRequests.begin(); it != g_activePolkitRequests.end(); ++it) {
            if ((*it)->id == qReq->id) {
                g_activePolkitRequests.erase(it);
                break;
            }
        }
    }

    if (!ok || !qReq->answered) {
        return brocred::PolkitAuthResponse::cancel("PolicyKit authentication request timed out");
    }
    return qReq->response;
}

Value buildRequestHandle(std::shared_ptr<PolkitQueuedRequest> req) {
    ObjectBuilder b;
    b.set("actionId", req->request.action_id);
    b.set("action_id", req->request.action_id);
    b.set("message", req->request.message);
    b.set("iconName", req->request.icon_name);
    b.set("icon_name", req->request.icon_name);
    b.set("cookie", req->request.cookie);

    ObjectBuilder details;
    for (const auto& [k, v] : req->request.details) {
        details.set(k, v);
    }
    b.set("details", details.get());

    ev::Persistent idArr(ev::makeArray(static_cast<uint32_t>(req->request.identities.size())));
    for (size_t i = 0; i < req->request.identities.size(); ++i) {
        const auto& id = req->request.identities[i];
        ObjectBuilder idObj;
        idObj.set("kind", id.kind == brocred::PolkitIdentity::Kind::UnixUser ? "user" : "group");
        idObj.set("id", static_cast<double>(id.id));
        idObj.set("name", id.name);
        idArr.set(ev::setElement(idArr.get(), static_cast<uint32_t>(i), idObj.get()));
    }
    b.set("identities", idArr.get());

    // req.submitResponse(response)
    b.def("submitResponse", 1, [req](Value, std::span<const Value> args) -> Value {
        ev::Persistent p0(args.size() > 0 ? args[0] : ev::undefined());

        brocred::PolkitAuthResponse resp;
        if (ev::isBool(p0.get())) {
            if (ev::toBool(p0.get())) {
                brocred::PolkitIdentity id = req->request.identities.empty()
                    ? brocred::PolkitIdentity::current_user()
                    : req->request.identities[0];
                resp = brocred::PolkitAuthResponse::ok(id);
            } else {
                resp = brocred::PolkitAuthResponse::cancel("Cancelled by user prompt");
            }
        } else if (ev::isObject(p0.get())) {
            ev::Persistent pSuccess(ev::getProperty(p0.get(), "success"));
            ev::Persistent pCancelled(ev::getProperty(p0.get(), "cancelled"));
            ev::Persistent pError(ev::getProperty(p0.get(), "error"));

            bool success = ev::isBool(pSuccess.get()) && ev::toBool(pSuccess.get());
            bool cancelled = ev::isBool(pCancelled.get()) && ev::toBool(pCancelled.get());
            std::string err = ev::isString(pError.get()) ? ev::toUtf8(pError.get()) : "";

            if (cancelled) {
                resp = brocred::PolkitAuthResponse::cancel(err.empty() ? "Cancelled by user" : err);
            } else if (success) {
                brocred::PolkitIdentity id = req->request.identities.empty()
                    ? brocred::PolkitIdentity::current_user()
                    : req->request.identities[0];
                resp = brocred::PolkitAuthResponse::ok(id);
            } else {
                resp = brocred::PolkitAuthResponse::fail(err.empty() ? "Authentication failed" : err);
            }
        } else {
            resp = brocred::PolkitAuthResponse::cancel("Invalid response format");
        }

        {
            std::lock_guard lock(req->mu);
            req->response = std::move(resp);
            req->answered = true;
        }
        req->cv.notify_all();
        return ev::fromBool(true);
    });

    // req.cancel([reason])
    b.def("cancel", 0, [req](Value, std::span<const Value> args) -> Value {
        ev::Persistent p0(args.size() > 0 ? args[0] : ev::undefined());
        std::string reason = ev::isString(p0.get()) ? ev::toUtf8(p0.get()) : "Cancelled by user";

        {
            std::lock_guard lock(req->mu);
            req->response = brocred::PolkitAuthResponse::cancel(reason);
            req->answered = true;
        }
        req->cv.notify_all();
        return ev::fromBool(true);
    });

    return b.get();
}

} // namespace

void drainPolkit() {
    std::vector<std::shared_ptr<PolkitQueuedRequest>> toDispatch;
    ev::Persistent callbackCopy;
    {
        std::lock_guard lock(g_polkitMu);
        toDispatch.swap(g_unhandledPolkitRequests);
        if (g_polkitCallback) {
            callbackCopy.set(g_polkitCallback->get());
        }
        if (g_polkitAgent && g_polkitAgent->is_running()) {
            g_polkitAgent->process_one(0);
        }
    }

    if (!toDispatch.empty() && !callbackCopy.get().isUndefined() && ev::isFunction(callbackCopy.get())) {
        for (auto& req : toDispatch) {
            ev::Persistent handleObj(buildRequestHandle(req));
            const Value arg = handleObj.get();
            ev::call(callbackCopy.get(), ev::undefined(), std::span<const Value>(&arg, 1));
        }
    }
}

void shutdownPolkit() {
    std::vector<std::shared_ptr<PolkitQueuedRequest>> toCancel;
    {
        std::lock_guard lock(g_polkitMu);
        if (g_polkitAgent) {
            g_polkitAgent->unregister_with_authority();
            g_polkitAgent->stop();
            g_polkitAgent.reset();
        }
        toCancel.swap(g_activePolkitRequests);
        g_unhandledPolkitRequests.clear();
        g_polkitCallback.reset();
    }

    for (auto& req : toCancel) {
        std::lock_guard lock(req->mu);
        req->response = brocred::PolkitAuthResponse::cancel("PolicyKit agent shutting down");
        req->answered = true;
        req->cv.notify_all();
    }
}

void installPolkitOnto(Value credObj) {
    ObjectBuilder cred(credObj);

    // bro.cred.registerPolkitAgent(options?) -> boolean
    cred.def("registerPolkitAgent", 0, [](Value, std::span<const Value> args) -> Value {
        ev::Persistent p0(args.size() > 0 ? args[0] : ev::undefined());

        brocred::PolkitAgentOptions opts;
        opts.register_with_authority = true;

        if (ev::isObject(p0.get())) {
            ev::Persistent pReg(ev::getProperty(p0.get(), "registerWithAuthority"));
            if (ev::isBool(pReg.get())) {
                opts.register_with_authority = ev::toBool(pReg.get());
            }
            ev::Persistent pPath(ev::getProperty(p0.get(), "objectPath"));
            if (ev::isString(pPath.get())) {
                opts.object_path = ev::toUtf8(pPath.get());
            }
            ev::Persistent pBus(ev::getProperty(p0.get(), "busAddress"));
            if (ev::isString(pBus.get())) {
                opts.bus_address = ev::toUtf8(pBus.get());
            }
            ev::Persistent pPass(ev::getProperty(p0.get(), "fallbackPassword"));
            if (ev::isString(pPass.get())) {
                opts.fallback_password = ev::toUtf8(pPass.get());
            }
        }

        std::lock_guard lock(g_polkitMu);
        if (!g_polkitAgent) {
            g_polkitAgent = brocred::PolkitAgent::create(opts, handleIncomingPolkitRequest);
        }
        if (!g_polkitAgent) return ev::fromBool(false);

        brocred::Result startRes = g_polkitAgent->start();
        if (!startRes.ok) return ev::fromBool(false);

        if (opts.register_with_authority) {
            brocred::Result regRes = g_polkitAgent->register_with_authority();
            return ev::fromBool(regRes.ok);
        }

        return ev::fromBool(true);
    });

    // bro.cred.unregisterPolkitAgent() -> boolean
    cred.def("unregisterPolkitAgent", 0, [](Value, std::span<const Value>) -> Value {
        std::lock_guard lock(g_polkitMu);
        if (!g_polkitAgent) return ev::fromBool(true);
        g_polkitAgent->unregister_with_authority();
        g_polkitAgent->stop();
        g_polkitAgent.reset();
        return ev::fromBool(true);
    });

    // bro.cred.isPolkitRegistered() -> boolean
    cred.def("isPolkitRegistered", 0, [](Value, std::span<const Value>) -> Value {
        std::lock_guard lock(g_polkitMu);
        return ev::fromBool(g_polkitAgent ? g_polkitAgent->is_registered() : false);
    });

    // bro.cred.onPolkitRequest(callback) -> RequestHandle (subscription handle)
    cred.def("onPolkitRequest", 1, [](Value, std::span<const Value> args) -> Value {
        ev::Persistent p0(args.size() > 0 ? args[0] : ev::undefined());
        if (!ev::isFunction(p0.get())) {
            return ev::throwTypeError("onPolkitRequest expects a function callback");
        }

        {
            std::lock_guard lock(g_polkitMu);
            g_polkitCallback = std::make_unique<ev::Persistent>(p0.get());
        }

        ObjectBuilder handle;
        handle.def("cancel", 0, [](Value, std::span<const Value>) -> Value {
            std::lock_guard lock(g_polkitMu);
            g_polkitCallback.reset();
            return ev::fromBool(true);
        });
        handle.def("dispose", 0, [](Value, std::span<const Value>) -> Value {
            std::lock_guard lock(g_polkitMu);
            g_polkitCallback.reset();
            return ev::fromBool(true);
        });
        handle.def("unregister", 0, [](Value, std::span<const Value>) -> Value {
            std::lock_guard lock(g_polkitMu);
            g_polkitCallback.reset();
            return ev::fromBool(true);
        });
        return handle.get();
    });

    // bro.cred.submitResponse(cookie, response) -> boolean
    cred.def("submitResponse", 2, [](Value, std::span<const Value> args) -> Value {
        ev::Persistent p0(args.size() > 0 ? args[0] : ev::undefined());
        ev::Persistent p1(args.size() > 1 ? args[1] : ev::undefined());

        std::string cookie = ev::isString(p0.get()) ? ev::toUtf8(p0.get()) : "";
        std::shared_ptr<PolkitQueuedRequest> found;
        {
            std::lock_guard lock(g_polkitMu);
            for (auto& req : g_activePolkitRequests) {
                if (req->request.cookie == cookie) {
                    found = req;
                    break;
                }
            }
        }
        if (!found) return ev::fromBool(false);

        brocred::PolkitAuthResponse resp;
        if (ev::isBool(p1.get())) {
            resp = ev::toBool(p1.get())
                ? brocred::PolkitAuthResponse::ok(found->request.identities.empty()
                    ? brocred::PolkitIdentity::current_user()
                    : found->request.identities[0])
                : brocred::PolkitAuthResponse::cancel("Cancelled by user prompt");
        } else {
            resp = brocred::PolkitAuthResponse::cancel("Cancelled");
        }

        {
            std::lock_guard lock(found->mu);
            found->response = std::move(resp);
            found->answered = true;
        }
        found->cv.notify_all();
        return ev::fromBool(true);
    });

    // bro.cred.cancelRequest(cookie) -> boolean
    cred.def("cancelRequest", 1, [](Value, std::span<const Value> args) -> Value {
        ev::Persistent p0(args.size() > 0 ? args[0] : ev::undefined());
        std::string cookie = ev::isString(p0.get()) ? ev::toUtf8(p0.get()) : "";
        std::shared_ptr<PolkitQueuedRequest> found;
        {
            std::lock_guard lock(g_polkitMu);
            for (auto& req : g_activePolkitRequests) {
                if (req->request.cookie == cookie) {
                    found = req;
                    break;
                }
            }
        }
        if (!found) return ev::fromBool(false);

        {
            std::lock_guard lock(found->mu);
            found->response = brocred::PolkitAuthResponse::cancel("Cancelled by user");
            found->answered = true;
        }
        found->cv.notify_all();
        return ev::fromBool(true);
    });

    // bro.cred.dispatchPolkitRequest(req) -> RequestHandle (test dispatch helper)
    cred.def("dispatchPolkitRequest", 1, [](Value, std::span<const Value> args) -> Value {
        ev::Persistent p0(args.size() > 0 ? args[0] : ev::undefined());
        brocred::PolkitAuthRequest req;
        if (ev::isObject(p0.get())) {
            ev::Persistent pAct(ev::getProperty(p0.get(), "actionId"));
            if (ev::isString(pAct.get())) req.action_id = ev::toUtf8(pAct.get());
            ev::Persistent pMsg(ev::getProperty(p0.get(), "message"));
            if (ev::isString(pMsg.get())) req.message = ev::toUtf8(pMsg.get());
            ev::Persistent pCook(ev::getProperty(p0.get(), "cookie"));
            if (ev::isString(pCook.get())) req.cookie = ev::toUtf8(pCook.get());
        }
        auto qReq = std::make_shared<PolkitQueuedRequest>();
        qReq->request = req;
        {
            std::lock_guard lock(g_polkitMu);
            qReq->id = ++g_nextPolkitReqId;
            g_activePolkitRequests.push_back(qReq);
            g_unhandledPolkitRequests.push_back(qReq);
        }
        return buildRequestHandle(qReq);
    });
}

} // namespace brocred::api
