#include "brocred/verifier.h"

#include <string>

#if !defined(BROCRED_HAVE_PAM)

namespace brocred {

// Built without PAM: there is no way to check a password, so say so.
VerifyResult verify_password(const std::string& password) {
    return verify_password("", "", password);
}

VerifyResult verify_password(const std::string& username, const std::string& password) {
    return verify_password(username, "", password);
}

VerifyResult verify_password(const std::string&, const std::string&, const std::string&) {
    return VerifyResult{false, "Password verification unavailable: brocred was built without PAM "
                               "(install the PAM development package and reconfigure)"};
}

}  // namespace brocred

#else

#include <security/pam_appl.h>
#include <pwd.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>

namespace brocred {

namespace {

struct PamAuthData {
    const char* password;
};

int pam_conversation_callback(int num_msg, const struct pam_message** msg,
                              struct pam_response** resp, void* appdata_ptr) {
    if (num_msg <= 0 || !resp || !appdata_ptr) return PAM_CONV_ERR;

    auto* responses = static_cast<struct pam_response*>(
        std::calloc(num_msg, sizeof(struct pam_response)));
    if (!responses) return PAM_BUF_ERR;

    auto* data = static_cast<const PamAuthData*>(appdata_ptr);

    for (int i = 0; i < num_msg; ++i) {
        if (!msg[i]) continue;
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF || msg[i]->msg_style == PAM_PROMPT_ECHO_ON) {
            responses[i].resp = data->password ? strdup(data->password) : nullptr;
            responses[i].resp_retcode = 0;
        }
    }

    *resp = responses;
    return PAM_SUCCESS;
}

std::string get_current_linux_user() {
    const char* user = getlogin();
    if (user && *user) return user;
    struct passwd* pw = getpwuid(getuid());
    if (pw && pw->pw_name) return pw->pw_name;
    const char* uenv = std::getenv("USER");
    if (uenv && *uenv) return uenv;
    return "";
}

}  // namespace

VerifyResult verify_password(const std::string& password) {
    return verify_password("", "", password);
}

VerifyResult verify_password(const std::string& username, const std::string& password) {
    return verify_password(username, "", password);
}

VerifyResult verify_password(const std::string& username, const std::string& domain_or_service,
                             const std::string& password) {
    std::string user = username.empty() ? get_current_linux_user() : username;
    if (user.empty()) {
        return VerifyResult{false, "Cannot determine username for authentication"};
    }

    PamAuthData auth_data{password.c_str()};
    struct pam_conv conv {
        &pam_conversation_callback,
        &auth_data
    };

    // Use domain_or_service if provided; otherwise check common standard service names
    const char* service = domain_or_service.empty() ? "system-auth" : domain_or_service.c_str();

    pam_handle_t* pamh = nullptr;
    int r = pam_start(service, user.c_str(), &conv, &pamh);
    if (r != PAM_SUCCESS && domain_or_service.empty()) {
        // Fallback service names on Debian/Ubuntu/other distributions
        const char* fallbacks[] = {"login", "passwd", "common-auth"};
        for (const char* fb : fallbacks) {
            r = pam_start(fb, user.c_str(), &conv, &pamh);
            if (r == PAM_SUCCESS) {
                service = fb;
                break;
            }
        }
    }

    if (r != PAM_SUCCESS || !pamh) {
        return VerifyResult{false, "pam_start failed for service '" + std::string(service) + "': " +
                                       (pamh ? pam_strerror(pamh, r) : "initialization error")};
    }

    r = pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK);
    std::string err_msg;
    if (r != PAM_SUCCESS) {
        err_msg = pam_strerror(pamh, r);
    }

    pam_end(pamh, r);

    if (r == PAM_SUCCESS) {
        return VerifyResult{true, ""};
    }
    return VerifyResult{false, err_msg.empty() ? "Authentication failed" : err_msg};
}

}  // namespace brocred

#endif  // BROCRED_HAVE_PAM
