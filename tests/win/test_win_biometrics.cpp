#include "check.h"
#include "brocred/biometrics.h"
#include "brocred/event_queue.h"

using namespace brocred;

static void test_biometric_capabilities() {
    BiometricCapabilities caps = get_biometric_capabilities();
    // Availability enum must be valid
    const char* str = to_string(caps.availability);
    REQUIRE(str != nullptr);
    CHECK(std::string(str) != "Unknown");

    // Async check
    EventQueue queue;
    check_biometrics_async(queue);
    bool received = queue.wait_for(std::chrono::milliseconds(5000));
    CHECK(received);

    auto events = queue.drain();
    REQUIRE(events.size() == 1);
    auto* bio_ev = std::get_if<BiometricStatusEvent>(&events[0]);
    REQUIRE(bio_ev != nullptr);
    CHECK_EQ(bio_ev->availability, caps.availability);
}

int main() {
    test_biometric_capabilities();
    return bstest::finish("test_win_biometrics");
}
