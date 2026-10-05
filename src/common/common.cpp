#include "brocred/common.h"
#include "brocred/biometrics.h"
#include "brocred/features.h"
#include "brocred/storage.h"
#include "brocred/verifier.h"

#include <atomic>
#include <thread>

namespace brocred {

const char* to_string(Availability a) {
    switch (a) {
        case Availability::Unknown:   return "Unknown";
        case Availability::No:        return "No";
        case Availability::Yes:       return "Yes";
        case Availability::NeedsAuth: return "NeedsAuth";
    }
    return "Unknown";
}

const char* to_string(BiometricAvailability a) {
    switch (a) {
        case BiometricAvailability::Unknown:          return "Unknown";
        case BiometricAvailability::NotAvailable:     return "NotAvailable";
        case BiometricAvailability::NotConfigured:    return "NotConfigured";
        case BiometricAvailability::Available:        return "Available";
        case BiometricAvailability::DisabledByPolicy: return "DisabledByPolicy";
    }
    return "Unknown";
}

const char* to_string(BiometricType t) {
    switch (t) {
        case BiometricType::None:        return "None";
        case BiometricType::Fingerprint: return "Fingerprint";
        case BiometricType::Face:        return "Face";
        case BiometricType::Iris:        return "Iris";
        case BiometricType::Multiple:    return "Multiple";
    }
    return "None";
}

Features compiled_features() {
    Features f;
#if defined(_WIN32) || defined(__APPLE__)
    f.native_secret_store = true;
    f.password_verification = true;
    f.biometrics_query = true;
#else
#if defined(BROCRED_HAVE_SDBUS)
    f.native_secret_store = true;
    f.biometrics_query = true;
#endif
#if defined(BROCRED_HAVE_PAM)
    f.password_verification = true;
#endif
#endif
    return f;
}

// Global convenience storage helpers
Result store_secret(const std::string& service, const std::string& account,
                    const std::string& secret) {
    auto store = CredentialStore::create();
    if (!store) return Result::failure("Cannot initialize credential store");
    return store->store_secret(service, account, secret);
}

Result store_secret(const std::string& service, const std::string& account,
                    const std::string& secret,
                    const std::map<std::string, std::string>& attributes) {
    auto store = CredentialStore::create();
    if (!store) return Result::failure("Cannot initialize credential store");
    return store->store_secret(service, account, secret, attributes);
}

std::optional<std::string> read_secret(const std::string& service,
                                       const std::string& account) {
    auto store = CredentialStore::create();
    if (!store) return std::nullopt;
    return store->read_secret(service, account);
}

Result delete_secret(const std::string& service, const std::string& account) {
    auto store = CredentialStore::create();
    if (!store) return Result::failure("Cannot initialize credential store");
    return store->delete_secret(service, account);
}

std::vector<CredentialMetadata> list_credentials() {
    auto store = CredentialStore::create();
    if (!store) return {};
    return store->list_credentials();
}

std::vector<CredentialMetadata> list_credentials(const std::string& service) {
    auto store = CredentialStore::create();
    if (!store) return {};
    return store->list_credentials(service);
}

// Asynchronous verifier helper
static std::atomic<uint64_t> g_next_request_id{1};

uint64_t verify_password_async(EventQueue& queue, const std::string& username,
                               const std::string& password) {
    uint64_t req_id = g_next_request_id.fetch_add(1);
    std::thread([&queue, req_id, username, password] {
        VerifyResult vr = verify_password(username, password);
        AuthPromptEvent event;
        event.request_id = req_id;
        event.success = vr.success;
        event.error = vr.error;
        queue.push(std::move(event));
    }).detach();
    return req_id;
}

// Asynchronous biometric check helper
void check_biometrics_async(EventQueue& queue) {
    std::thread([&queue] {
        BiometricCapabilities caps = get_biometric_capabilities();
        BiometricStatusEvent ev;
        ev.availability = caps.availability;
        ev.details = caps.details;
        queue.push(std::move(ev));
    }).detach();
}

}  // namespace brocred
