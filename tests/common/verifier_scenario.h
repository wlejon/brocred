// Shared body of the per-platform password-verifier tests.
//
// By default only an account that does not exist is tried: the full native
// path runs (LogonUserW / PAM / OpenDirectory) and must fail with an error,
// but no real account's failed-logon counter moves. Wrong-password attempts
// against the logged-in user count toward lockout policies (Windows 11 locks
// after 10 by default, pam_faillock after 3 on some distros) and land in the
// security log, so they run only with BROCRED_TEST_AUTH=1.
#pragma once

#include "check.h"
#include "brocred/event_queue.h"
#include "brocred/verifier.h"

#include <chrono>
#include <string>

namespace brocred_test {

inline constexpr const char* kNoSuchUser = "brocred_no_such_user_7f3a9c";

inline void check_async(const std::string& user, const std::string& password) {
    brocred::EventQueue queue;
    uint64_t req_id = brocred::verify_password_async(queue, user, password);
    CHECK(req_id > 0);
    bool received = queue.wait_for(std::chrono::milliseconds(10000));
    CHECK(received);
    auto events = queue.drain();
    REQUIRE(events.size() == 1);
    auto* auth_ev = std::get_if<brocred::AuthPromptEvent>(&events[0]);
    REQUIRE(auth_ev != nullptr);
    CHECK_EQ(auth_ev->request_id, req_id);
    CHECK(!auth_ev->success);
    CHECK(!auth_ev->error.empty());
}

inline int run_verifier_scenario(const char* name) {
    {
        brocred::VerifyResult vr = brocred::verify_password(kNoSuchUser, "irrelevant_password_1");
        std::printf("unknown user -> success=%d error='%s'\n", vr.success, vr.error.c_str());
        CHECK(!vr.success);
        CHECK(!vr.error.empty());
        check_async(kNoSuchUser, "irrelevant_password_2");
    }

    if (bstest::opted_in("BROCRED_TEST_AUTH")) {
        brocred::VerifyResult vr = brocred::verify_password("definitely_wrong_password_12345");
        std::printf("current user, wrong password -> success=%d error='%s'\n", vr.success, vr.error.c_str());
        CHECK(!vr.success);
        CHECK(!vr.error.empty());
        check_async("", "another_bad_password_98765");
    } else {
        std::printf("[%s] note: wrong-password attempts against the logged-in account skipped; "
                    "set BROCRED_TEST_AUTH=1 to run them\n", name);
    }
    return bstest::finish(name);
}

}  // namespace brocred_test
