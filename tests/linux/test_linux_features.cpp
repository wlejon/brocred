// The feature report must match what this configuration was built with, and
// each compiled-out integration must degrade the way features.h documents.
#include "check.h"
#include "brocred/biometrics.h"
#include "brocred/features.h"
#include "brocred/storage.h"
#include "brocred/verifier.h"

#include <cstdlib>
#include <filesystem>
#include <string>
#include <unistd.h>

using namespace brocred;

static void test_feature_report() {
    Features f = compiled_features();
    std::printf("native_secret_store=%d password_verification=%d biometrics_query=%d\n",
                f.native_secret_store, f.password_verification, f.biometrics_query);
    CHECK_EQ(f.native_secret_store, static_cast<bool>(EXPECT_SDBUS));
    CHECK_EQ(f.biometrics_query, static_cast<bool>(EXPECT_SDBUS));
    CHECK_EQ(f.password_verification, static_cast<bool>(EXPECT_PAM));
}

static void test_without_sdbus() {
    if (compiled_features().native_secret_store) return;

    // Auto falls back to the file keystore; point it at a private path so the
    // test leaves nothing in the user's data directory.
    char tmpl[] = "/tmp/brocred_features_XXXXXX";
    char* dir = mkdtemp(tmpl);
    REQUIRE(dir != nullptr);
    struct Cleanup {
        std::string dir;
        ~Cleanup() {
            std::error_code ec;
            std::filesystem::remove_all(dir, ec);
        }
    } cleanup{dir};

    StorageOptions auto_opts;
    auto_opts.custom_file_path = std::string(dir) + "/store";
    auto store = CredentialStore::create(auto_opts);
    REQUIRE(store != nullptr);
    CHECK_EQ(store->backend_name(), std::string("FileKeystore"));
    CHECK(store->store_secret("brocred_features_svc", "acct", "s3cret").ok);
    auto back = store->read_secret("brocred_features_svc", "acct");
    CHECK(back.has_value() && *back == "s3cret");
    CHECK(store->delete_secret("brocred_features_svc", "acct").ok);

    // System must refuse rather than silently use a file.
    StorageOptions sys_opts;
    sys_opts.backend = BackendType::System;
    sys_opts.custom_file_path = std::string(dir) + "/never";
    auto sys = CredentialStore::create(sys_opts);
    REQUIRE(sys != nullptr);
    Result r = sys->store_secret("brocred_features_svc", "acct", "x");
    CHECK(!r.ok);
    CHECK(r.error.find("sd-bus") != std::string::npos);
    CHECK(!std::filesystem::exists(std::string(dir) + "/never"));

    BiometricCapabilities caps = get_biometric_capabilities();
    CHECK_EQ(caps.availability, BiometricAvailability::Unknown);
    CHECK(caps.details.find("sd-bus") != std::string::npos);
}

static void test_without_pam() {
    if (compiled_features().password_verification) return;
    VerifyResult vr = verify_password("anything");
    CHECK(!vr.success);
    CHECK(vr.error.find("PAM") != std::string::npos);
}

int main() {
    test_feature_report();
    test_without_sdbus();
    test_without_pam();
    return bstest::finish("test_linux_features");
}
