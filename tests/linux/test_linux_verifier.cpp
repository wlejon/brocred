#include "check.h"
#include "brocred/event_queue.h"
#include "brocred/verifier.h"

using namespace brocred;

static void test_pam_verification_failure() {
    VerifyResult vr = verify_password("definitely_wrong_password_12345");
    CHECK(!vr.success);
    CHECK(!vr.error.empty());
}

static void test_pam_async_verification() {
    EventQueue queue;
    uint64_t req_id = verify_password_async(queue, "", "another_bad_password_98765");
    CHECK(req_id > 0);

    bool received = queue.wait_for(std::chrono::milliseconds(5000));
    CHECK(received);

    auto events = queue.drain();
    REQUIRE(events.size() == 1);

    auto* auth_ev = std::get_if<AuthPromptEvent>(&events[0]);
    REQUIRE(auth_ev != nullptr);
    CHECK_EQ(auth_ev->request_id, req_id);
    CHECK(!auth_ev->success);
    CHECK(!auth_ev->error.empty());
}

int main() {
    test_pam_verification_failure();
    test_pam_async_verification();
    return bstest::finish("test_linux_verifier");
}
