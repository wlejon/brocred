#include "api.h"
#include "host_cred_internal.h"

#include <mutex>
#include <vector>

namespace brocred::api {

namespace {

std::mutex g_storeMu;
std::shared_ptr<brocred::CredentialStore> g_customStore;

std::mutex g_jobsMu;
uint64_t g_nextJobId = 1;
std::vector<std::shared_ptr<CredAsyncJob>> g_jobs;

brocred::EventQueue& globalEventQueue() {
    static brocred::EventQueue q;
    return q;
}

} // namespace

brocred::EventQueue& credEventQueue() {
    return globalEventQueue();
}

std::shared_ptr<brocred::CredentialStore> activeStore() {
    std::lock_guard lock(g_storeMu);
    if (g_customStore) return g_customStore;
    static std::shared_ptr<brocred::CredentialStore> defStore = brocred::CredentialStore::create();
    return defStore;
}

void setStore(std::shared_ptr<brocred::CredentialStore> store) {
    std::lock_guard lock(g_storeMu);
    g_customStore = std::move(store);
}

std::shared_ptr<brocred::CredentialStore> getStore() {
    return activeStore();
}

Value makeError(const std::string& msg) {
    ev::Persistent text(ev::fromUtf8(msg));
    auto ctor = ev::globalValue("Error");
    if (ctor.found && ev::isFunction(ctor.value)) {
        ev::Persistent c(ctor.value);
        const Value arg = text.get();
        auto r = ev::construct(c.get(), std::span<const Value>(&arg, 1));
        if (!r.thrown) return r.value;
    }
    return text.get();
}

Value ensureBroCred() {
    ev::Persistent globalThisVal;
    auto gt = ev::globalValue("globalThis");
    if (gt.found && ev::isObject(gt.value)) {
        globalThisVal.set(gt.value);
    }

    ev::Persistent broP;
    auto bro = ev::globalValue("bro");
    if (bro.found && ev::isObject(bro.value)) broP.set(bro.value);
    if (!ev::isObject(broP.get()) && ev::isObject(globalThisVal.get())) {
        Value candidate = ev::getProperty(globalThisVal.get(), "bro");
        if (ev::isObject(candidate)) broP.set(candidate);
    }
    if (!ev::isObject(broP.get())) {
        broP.set(ev::createObject());
        ev::registerGlobal("bro", broP.get());
        if (ev::isObject(globalThisVal.get())) {
            globalThisVal.set(ev::setProperty(globalThisVal.get(), "bro", broP.get()));
        }
    }

    ev::Persistent credP(ev::getProperty(broP.get(), "cred"));
    if (!ev::isObject(credP.get())) {
        credP.set(ev::createObject());
        broP.set(ev::setProperty(broP.get(), "cred", credP.get()));
    }
    return credP.get();
}

void trackAsyncJob(std::shared_ptr<CredAsyncJob> job) {
    std::lock_guard lock(g_jobsMu);
    job->id = ++g_nextJobId;
    if (job->run) {
        job->worker = std::thread([job]() {
            try {
                job->run();
            } catch (const std::exception& e) {
                job->error = e.what();
            } catch (...) {
                job->error = "Unknown exception in background cred task";
            }
            job->done.store(true, std::memory_order_release);
        });
    } else {
        job->done.store(true, std::memory_order_release);
    }
    g_jobs.push_back(std::move(job));
}

bool drainAsyncJobs() {
    std::vector<std::shared_ptr<CredAsyncJob>> completed;
    {
        std::lock_guard lock(g_jobsMu);
        std::vector<std::shared_ptr<CredAsyncJob>> remaining;
        for (auto& j : g_jobs) {
            if (j->done.load(std::memory_order_acquire)) {
                completed.push_back(std::move(j));
            } else {
                remaining.push_back(std::move(j));
            }
        }
        g_jobs = std::move(remaining);
    }

    if (completed.empty()) return false;

    for (auto& job : completed) {
        if (job->worker.joinable()) {
            job->worker.join();
        }
        if (!job->error.empty()) {
            ev::Persistent err(makeError(job->error));
            ev::rejectPromise(job->promise.get(), err.get());
        } else if (job->settle) {
            job->settle(job->promise.get());
        }
    }
    return true;
}

void cancelAllAsyncJobs() {
    std::vector<std::shared_ptr<CredAsyncJob>> jobs;
    {
        std::lock_guard lock(g_jobsMu);
        jobs = std::move(g_jobs);
        g_jobs.clear();
    }
    for (auto& j : jobs) {
        if (j->worker.joinable()) {
            j->worker.join();
        }
    }
}

void installCred() {
    ev::Persistent credObj(ensureBroCred());
    installAuthOnto(credObj.get());
    installBiometricsOnto(credObj.get());
    installSecretsOnto(credObj.get());
    installPolkitOnto(credObj.get());
}

void tickCredAsync() {
    drainAsyncJobs();

    // Drain native EventQueue
    auto nativeEvents = credEventQueue().drain();
    for (const auto& evItem : nativeEvents) {
        if (std::holds_alternative<brocred::AuthPromptEvent>(evItem)) {
            handleAuthEvent(std::get<brocred::AuthPromptEvent>(evItem));
        } else if (std::holds_alternative<brocred::BiometricStatusEvent>(evItem)) {
            handleBiometricEvent(std::get<brocred::BiometricStatusEvent>(evItem));
        } else if (std::holds_alternative<brocred::CredentialChangedEvent>(evItem)) {
            handleCredentialChangedEvent(std::get<brocred::CredentialChangedEvent>(evItem));
        }
    }

    drainAuth();
    drainBiometrics();
    drainPolkit();
}

void shutdownCredAsync() {
    shutdownPolkit();
    shutdownAuth();
    shutdownBiometrics();
    cancelAllAsyncJobs();
}

} // namespace brocred::api
