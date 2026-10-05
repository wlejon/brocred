// Which system integrations this build of brocred was compiled with.
#pragma once

namespace brocred {

// Compile-time capabilities. A feature compiled out is reported here and its
// API answers honestly at runtime (fallback store, explanatory error, or an
// Unknown biometric state) instead of failing to build.
//
// On Windows and macOS every integration is part of the OS and always built.
// On Linux they depend on optional development packages:
//   native_secret_store  Secret Service over sd-bus (libsystemd); without it
//                        CredentialStore Auto uses the file keystore and
//                        BackendType::System fails.
//   password_verification PAM; without it verify_password() fails.
//   biometrics_query     fprintd over sd-bus; without it biometrics report
//                        BiometricAvailability::Unknown.
// Being compiled in does not mean the service is running; the runtime APIs
// (backend_name(), get_biometric_capabilities()) report that.
struct Features {
    bool native_secret_store = false;
    bool password_verification = false;
    bool biometrics_query = false;
};

Features compiled_features();

}  // namespace brocred
