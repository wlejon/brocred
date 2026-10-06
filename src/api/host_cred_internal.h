#pragma once

#include "embed/embed.h"
#include "host_class.h"
#include "object_builder.h"
#include "arg_reader.h"
#include "brocred/brocred.h"

#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace brocred::api {

namespace ev = bronze::embed;
using Value = bronze::Value;

Value makeError(const std::string& msg);
Value ensureBroCred();

std::shared_ptr<brocred::CredentialStore> activeStore();
void setStore(std::shared_ptr<brocred::CredentialStore> store);
std::shared_ptr<brocred::CredentialStore> getStore();

struct CredAsyncJob {
    uint64_t id{0};
    ev::Persistent promise;
    std::atomic<bool> done{false};
    std::thread worker;
    std::string error;
    std::function<void()> run;
    std::function<void(Value promiseVal)> settle;
};

void trackAsyncJob(std::shared_ptr<CredAsyncJob> job);
bool drainAsyncJobs();
void cancelAllAsyncJobs();

brocred::EventQueue& credEventQueue();

void installAuthOnto(Value credObj);
void installBiometricsOnto(Value credObj);
void installSecretsOnto(Value credObj);
void installPolkitOnto(Value credObj);

void handleAuthEvent(const brocred::AuthPromptEvent& evItem);
void handleBiometricEvent(const brocred::BiometricStatusEvent& evItem);
void handleCredentialChangedEvent(const brocred::CredentialChangedEvent& evItem);

void drainAuth();
void shutdownAuth();

void drainBiometrics();
void shutdownBiometrics();

void drainPolkit();
void shutdownPolkit();

} // namespace brocred::api
