// Implementation of default PolicyKit conversation and PAM verification.
#include "linux/polkit/polkit_conversation.h"
#include "brocred/storage.h"

#include <pwd.h>
#include <unistd.h>

namespace brocred::polkit {

PolkitAuthResponse default_conversation_handler(const PolkitAuthRequest& request,
                                               const std::string& fallback_password) {
    if (request.identities.empty()) {
        return PolkitAuthResponse::fail("No target identities provided for authentication");
    }

    // Select candidate identity: prefer current user if present, otherwise first identity
    uint32_t my_uid = static_cast<uint32_t>(getuid());
    const PolkitIdentity* target = &request.identities.front();
    for (const auto& id : request.identities) {
        if (id.kind == PolkitIdentity::Kind::UnixUser && id.id == my_uid) {
            target = &id;
            break;
        }
    }

    std::string user = target->name;
    if (user.empty() && target->kind == PolkitIdentity::Kind::UnixUser) {
        struct passwd* pw = getpwuid(target->id);
        if (pw && pw->pw_name) user = pw->pw_name;
    }

    if (user.empty()) {
        return PolkitAuthResponse::fail("Cannot resolve target username for authentication");
    }

    if (!fallback_password.empty()) {
        VerifyResult vres = verify_password(user, fallback_password);
        if (vres.success) {
            return PolkitAuthResponse::ok(*target);
        }
        return PolkitAuthResponse::fail("Password verification failed for user " + user + ": " + vres.error);
    }

    // Attempt credential lookup in default store
    std::string stored_secret;
    auto store = CredentialStore::create();
    if (store) {
        auto sec = store->read_secret("polkit", user);
        if (!sec) sec = store->read_secret("pam", user);
        if (sec && !sec->empty()) {
            VerifyResult vres = verify_password(user, *sec);
            if (vres.success) {
                return PolkitAuthResponse::ok(*target);
            }
        }
    }

    return PolkitAuthResponse::fail("Authentication required but no credentials or prompt callback available");
}

}  // namespace brocred::polkit
