#include "host_cred_internal.h"
#include "brocred/biometrics.h"

#include <mutex>
#include <vector>

namespace brocred::api {

namespace {

struct PendingBioAuth {
    ev::Persistent promise;
    std::atomic<bool> cancelled{false};
    brocred::BiometricCapabilities caps;
};

std::mutex g_bioMu;
std::vector<std::shared_ptr<PendingBioAuth>> g_pendingBioAuth;
std::vector<brocred::BiometricStatusEvent> g_queuedBioEvents;

} // namespace

void handleBiometricEvent(const brocred::BiometricStatusEvent& evItem) {
    std::lock_guard lock(g_bioMu);
    g_queuedBioEvents.push_back(evItem);
}

void drainBiometrics() {
    std::vector<brocred::BiometricStatusEvent> events;
    std::vector<std::shared_ptr<PendingBioAuth>> pending;
    {
        std::lock_guard lock(g_bioMu);
        events.swap(g_queuedBioEvents);
        pending = g_pendingBioAuth;
        g_pendingBioAuth.clear();
    }

    if (pending.empty()) return;

    for (auto& item : pending) {
        if (item->cancelled.load()) {
            ObjectBuilder res;
            res.set("success", false);
            res.set("method", "none");
            res.set("cancelled", true);
            res.set("error", "Biometric authentication cancelled");
            ev::resolvePromise(item->promise.get(), res.get());
        } else {
            ObjectBuilder res;
            bool isAvailable = (item->caps.availability == brocred::BiometricAvailability::Available);
            if (!events.empty()) {
                isAvailable = (events.back().availability == brocred::BiometricAvailability::Available);
            }
            res.set("success", isAvailable);
            res.set("method", brocred::to_string(item->caps.primary_type));
            res.set("availability", brocred::to_string(item->caps.availability));
            res.set("details", item->caps.details);
            ev::resolvePromise(item->promise.get(), res.get());
        }
    }
}

void shutdownBiometrics() {
    std::vector<std::shared_ptr<PendingBioAuth>> pending;
    {
        std::lock_guard lock(g_bioMu);
        pending.swap(g_pendingBioAuth);
        g_queuedBioEvents.clear();
    }
    for (auto& item : pending) {
        ObjectBuilder res;
        res.set("success", false);
        res.set("method", "none");
        res.set("cancelled", true);
        res.set("error", "Biometric service shutting down");
        ev::resolvePromise(item->promise.get(), res.get());
    }
}

void installBiometricsOnto(Value credObj) {
    ObjectBuilder cred(credObj);

    // bro.cred.getBiometrics() -> { hasFingerprint: boolean, hasFace: boolean, ... }
    cred.def("getBiometrics", 0, [](Value, std::span<const Value>) -> Value {
        brocred::BiometricCapabilities caps = brocred::get_biometric_capabilities();
        ObjectBuilder b;
        b.set("supported", caps.supported);
        b.set("hasFingerprint", caps.has_fingerprint);
        b.set("hasFace", caps.has_face);
        b.set("hasIris", caps.has_iris);
        b.set("has_fingerprint", caps.has_fingerprint);
        b.set("has_face", caps.has_face);
        b.set("has_iris", caps.has_iris);
        b.set("availability", brocred::to_string(caps.availability));
        b.set("primaryType", brocred::to_string(caps.primary_type));
        b.set("primary_type", brocred::to_string(caps.primary_type));
        b.set("sensorName", caps.sensor_name);
        b.set("sensor_name", caps.sensor_name);
        b.set("details", caps.details);
        return b.get();
    });

    // bro.cred.startBiometricAuth() -> Promise<{ success: boolean, method: string }>
    cred.def("startBiometricAuth", 0, [](Value, std::span<const Value>) -> Value {
        ev::Persistent promise(ev::createPromise());

        brocred::BiometricCapabilities caps = brocred::get_biometric_capabilities();
        auto item = std::make_shared<PendingBioAuth>();
        item->promise.set(promise.get());
        item->caps = caps;

        {
            std::lock_guard lock(g_bioMu);
            g_pendingBioAuth.push_back(item);
        }

        // Trigger async check on native event queue
        brocred::check_biometrics_async(credEventQueue());

        return promise.get();
    });

    // bro.cred.cancelBiometricAuth() -> void
    cred.def("cancelBiometricAuth", 0, [](Value, std::span<const Value>) -> Value {
        std::vector<std::shared_ptr<PendingBioAuth>> toCancel;
        {
            std::lock_guard lock(g_bioMu);
            for (auto& item : g_pendingBioAuth) {
                item->cancelled.store(true);
                toCancel.push_back(item);
            }
            g_pendingBioAuth.clear();
        }

        for (auto& item : toCancel) {
            ObjectBuilder res;
            res.set("success", false);
            res.set("method", "none");
            res.set("cancelled", true);
            res.set("error", "Biometric authentication cancelled");
            ev::resolvePromise(item->promise.get(), res.get());
        }

        return ev::undefined();
    });
}

} // namespace brocred::api
