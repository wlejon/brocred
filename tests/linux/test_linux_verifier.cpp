#include "common/verifier_scenario.h"
#include "brocred/features.h"

int main() {
    if (!brocred::compiled_features().password_verification) {
        bstest::skip("test_linux_verifier", "built without PAM; test_linux_features covers that configuration");
    }
    return brocred_test::run_verifier_scenario("test_linux_verifier");
}
