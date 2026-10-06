// The PolicyKit authentication agent and the Secret Service provider where
// they cannot exist: Windows and macOS (no PolicyKit, no org.freedesktop.secrets),
// and Linux builds without sd-bus. Compiled instead of src/linux/polkit and
// src/linux/secret_service; compiled_features() reports both as absent.
//
// The factories still return objects, so callers need no platform #ifdefs:
// start() and the registration calls fail with the reason, nothing ever runs,
// and the provider hands back the store it was given (or none).
#include "brocred/polkit_agent.h"
#include "brocred/secret_service.h"

#if defined(_WIN32)
#include <process.h>
#else
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#endif

#include <cstdlib>
#include <utility>

namespace brocred {

namespace {

const char* unavailable_reason() {
#if defined(_WIN32)
    return "PolicyKit and the Secret Service are Linux desktop services; Windows has neither";
#elif defined(__APPLE__)
    return "PolicyKit and the Secret Service are Linux desktop services; macOS has neither";
#else
    return "brocred was built without sd-bus (libsystemd), which the PolicyKit agent and the "
           "Secret Service provider speak";
#endif
}

class UnavailablePolkitAgent final : public PolkitAgent {
public:
    Result start() override { return Result::failure(unavailable_reason()); }
    void stop() override {}
    bool is_running() const override { return false; }
    Result register_with_authority() override { return Result::failure(unavailable_reason()); }
    Result unregister_with_authority() override { return Result::failure(unavailable_reason()); }
    bool is_registered() const override { return false; }
    bool process_one(uint64_t) override { return false; }
    PolkitAuthResponse handle_begin_authentication(const PolkitAuthRequest&) override {
        return PolkitAuthResponse::fail(unavailable_reason());
    }
    void handle_cancel_authentication(const std::string&) override {}
    bool has_active_session(const std::string&) const override { return false; }
};

class UnavailableSecretService final : public SecretServiceProvider {
public:
    explicit UnavailableSecretService(std::unique_ptr<CredentialStore> store)
        : store_(std::move(store)) {}

    Result start() override { return Result::failure(unavailable_reason()); }
    void stop() override {}
    bool is_running() const override { return false; }
    bool process_one(uint64_t) override { return false; }
    CredentialStore* store() override { return store_.get(); }
    std::vector<std::string> list_collection_paths() const override { return {}; }
    std::vector<std::string> list_item_paths(const std::string&) const override { return {}; }

private:
    std::unique_ptr<CredentialStore> store_;
};

}  // namespace

// The subject and identity types are plain data and stay usable everywhere.
// Windows has no Unix uid/gid, so names are not looked up there and the
// current user is reported by name with the "no uid" value.

PolkitSubject PolkitSubject::current_process() {
#if defined(_WIN32)
    return process(static_cast<uint32_t>(_getpid()));
#else
    return process(static_cast<uint32_t>(getpid()));
#endif
}

PolkitSubject PolkitSubject::process(uint32_t pid, uint64_t start_time) {
    PolkitSubject s;
    s.kind = Kind::UnixProcess;
    s.pid = pid;
    s.start_time = start_time;
    return s;
}

PolkitSubject PolkitSubject::session(std::string session_id) {
    PolkitSubject s;
    s.kind = Kind::UnixSession;
    s.session_id = std::move(session_id);
    return s;
}

PolkitIdentity PolkitIdentity::user(uint32_t uid, std::string name) {
    PolkitIdentity id;
    id.kind = Kind::UnixUser;
    id.id = uid;
#if !defined(_WIN32)
    if (name.empty()) {
        if (struct passwd* pw = getpwuid(uid); pw && pw->pw_name) name = pw->pw_name;
    }
#endif
    id.name = std::move(name);
    return id;
}

PolkitIdentity PolkitIdentity::group(uint32_t gid, std::string name) {
    PolkitIdentity id;
    id.kind = Kind::UnixGroup;
    id.id = gid;
#if !defined(_WIN32)
    if (name.empty()) {
        if (struct group* gr = getgrgid(gid); gr && gr->gr_name) name = gr->gr_name;
    }
#endif
    id.name = std::move(name);
    return id;
}

PolkitIdentity PolkitIdentity::current_user() {
#if defined(_WIN32)
    const char* name = std::getenv("USERNAME");
    return user(UINT32_MAX, name ? name : "");
#else
    return user(static_cast<uint32_t>(getuid()));
#endif
}

std::unique_ptr<PolkitAgent> PolkitAgent::create(const PolkitAgentOptions&, PolkitAuthHandler) {
    return std::make_unique<UnavailablePolkitAgent>();
}

std::unique_ptr<SecretServiceProvider> SecretServiceProvider::create(
    const SecretServiceOptions&) {
    return std::make_unique<UnavailableSecretService>(nullptr);
}

std::unique_ptr<SecretServiceProvider> SecretServiceProvider::create(
    std::unique_ptr<CredentialStore> store, const SecretServiceOptions&) {
    return std::make_unique<UnavailableSecretService>(std::move(store));
}

}  // namespace brocred
