# brocred

[![CI](https://github.com/wlejon/brocred/actions/workflows/ci.yml/badge.svg)](https://github.com/wlejon/brocred/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Cross-platform credential management, secure secret storage, lock-screen password verification,
and biometric capability detection. A standalone C++20 library providing native operating
system integrations for Linux, Windows, and macOS with zero required dependencies on bro or
bronze.

brocred sits in the desktop-environment layer of the
[bro ecosystem](https://github.com/wlejon/bro/blob/main/docs/ecosystem.md). It is consumed by
the [bro runtime](https://github.com/wlejon/bro) under the `BRO_WITH_CRED` build gate. The
engine mounts its JavaScript binding (`brocred_api` in `src/api/`) onto `bro.cred`, providing
desktop applications with secure credential access and authentication primitives through
bronze.

## Architecture & API Overview

`brocred` uses the same asynchronous, non-blocking patterns as `brosys`:
- **Asynchronous Event Delivery:** Long-running calls and notifications push events into a
  thread-safe `MessageQueue<T>` (`event_queue.h`), drained by the host thread via an optional
  wake hook.
- **Honest Capability Reporting:** Public APIs query underlying system capabilities directly
  without synthetic mocks. Feature availability is reported by `compiled_features()`
  (`features.h`) and runtime status queries.
- **Decomposed Architecture:** Clean separation of concerns with all source files strictly
  under 1,000 lines of code.

```
include/brocred/
  brocred.h         Umbrella header
  common.h          Result, Availability, BiometricAvailability, BiometricType
  credential.h      Credential value type, CredentialMetadata
  event_queue.h     MessageQueue<T> (thread-safe MPSC queue with wake hook)
  events.h          CredentialChangedEvent, AuthPromptEvent, BiometricStatusEvent
  features.h        compiled_features(): compile-time feature query
  storage.h         CredentialStore interface, default_store(), memory/file keystores
  verifier.h        verify_password, verify_password_async (lock-screen verification)
  biometrics.h      get_biometric_capabilities, check_biometrics_async
  polkit_agent.h    PolkitAgent: PolicyKit authentication agent for desktop shells (Linux)
  secret_service.h  SecretServiceProvider: exports org.freedesktop.secrets over D-Bus (Linux)
  api.h             Bronze JavaScript binding entry point (brocred_api)
```

## Backend Implementation Matrix

| Capability | Linux | Windows | macOS |
|---|---|---|---|
| **Secret Storage** | FreeDesktop Secret Service (`org.freedesktop.secrets` via `brodbus` + `sd-bus`), with fallback to `FileKeystore` (`0600` permissions) | Windows Credential Manager (`CredWriteW`, `CredReadW`, `CredDeleteW`, `CredEnumerateW`) | Apple Keychain Services (`SecItemAdd`, `SecItemCopyMatching`, `SecItemDelete`, `SecItemUpdate`) |
| **Password Verification** | Linux PAM (`pam_start`, `pam_authenticate` via `/etc/pam.d/login`) | Win32 `LogonUserW` (`LOGON32_LOGON_NETWORK` / `LOGON32_LOGON_INTERACTIVE`) | OpenDirectory framework (`ODSession`, `ODNode`, `ODRecordVerifyPassword`) |
| **Biometrics Detection** | `fprintd` over system D-Bus (`net.reactivated.Fprint.Manager` via `brodbus`) | Windows Hello (`UserConsentVerifier`) & Windows Biometric Framework (`WinBioEnumBiometricUnits`) | LocalAuthentication framework (`LAContext canEvaluatePolicy:`) |
| **Desktop Shell Agents** | `PolkitAgent` (PolicyKit1 agent) & `SecretServiceProvider` (D-Bus secrets provider) | Unsupported (returns explanatory error) | Unsupported (returns explanatory error) |

### Secret Storage Details

- **Windows Credential Manager:** Stored with format `service:account` or custom target names.
  Handles UTF-16LE and UTF-8 conversion transparently for interoperability with `cmdkey.exe`
  and third-party Windows software. Custom attributes use `CREDENTIAL_ATTRIBUTEW`.
- **macOS Keychain:** Stores generic passwords (`kSecClassGenericPassword`). Custom attributes
  and metadata serialize to structured JSON in `kSecAttrGeneric`. Non-interactive testing
  supports isolated keychain search lists (`SecKeychainCopySearchList`).
- **Linux Secret Service & Keystores:** Connects to the D-Bus session bus via `brodbus` and
  `sd-bus` to communicate with GNOME Keyring or KWallet. Enforces strict 2-second timeouts to
  prevent hangs in headless environments. When no daemon is available, falls back to
  `FileKeystore` (`~/.local/share/brocred/credentials.store` with POSIX `0600` mode and atomic
  temp staging) or `MemoryKeystore`.

### Linux Desktop Shell Agents

For desktop shells acting as their own session, brocred provides standard Linux session
services:
- **`PolkitAgent`:** Registers as `org.freedesktop.PolicyKit1.AuthenticationAgent`, routing
  authentication requests to the shell's prompt handler and completing them with PolicyKit.
- **`SecretServiceProvider`:** Serves `org.freedesktop.secrets` (collections, items, `plain`
  and `dh-ietf1024-sha256-aes128-cbc-pkcs7` sessions backed by OpenSSL libcrypto), allowing
  browsers and `secret-tool` to store credentials in any `CredentialStore`.

## Building & Dependencies

brocred requires CMake 3.24+ and a C++20 compiler.

### Dependencies

- **Linux:**
  - Requires **[brodbus](https://github.com/wlejon/brodbus)** on Linux when building with D-Bus support (`BROCRED_WITH_SDBUS`).
  - Requires `libsystemd-dev` (sd-bus >= 246) and `libssl-dev` (OpenSSL libcrypto for DH secret service sessions).
  - Requires `libpam0g-dev` for PAM password verification (`BROCRED_WITH_PAM`).
- **Windows:** MSVC 2022+; links `advapi32`, `credui`, `user32`.
- **macOS:** Apple Clang (macOS 13+); links `Security`, `OpenDirectory`, `LocalAuthentication`, `Foundation`.

### Dependency Resolution (brodbus)

On Linux with sd-bus, `brocred` needs the `brodbus` library. There are no submodules:
brodbus (and bronze, for the JavaScript binding) is a `bro_dependency()` pin in
`CMakeLists.txt`, resolved through `cmake/bro_deps.cmake` in this order:
1. **Existing target:** Uses `brodbus` if already defined by a parent build.
2. **Working tree:** `../brodbus` beside the top-level project (or `-DFETCHCONTENT_SOURCE_DIR_BRODBUS=<path>`).
3. **Pinned commit:** fetched from GitHub at configure, so a plain `git clone` builds.

### Standalone Build

```bash
# Linux (GCC / Clang + Ninja)
sudo apt install libsystemd-dev libpam0g-dev libssl-dev pkg-config ninja-build
cmake -B build-release -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-release
ctest --test-dir build-release --output-on-failure

# Windows (Visual Studio 2022)
cmake -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure

# macOS (Apple Clang + Ninja)
cmake -B build-release -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-release
ctest --test-dir build-release --output-on-failure
```

### Consuming brocred

Downstream consumers link against `brocred::brocred`:

```cmake
add_subdirectory(path/to/brocred)
target_link_libraries(your_target PRIVATE brocred::brocred)
```

The standalone Bronze JavaScript binding (`BROCRED_ENABLE_API`, on when brocred is the
top-level project) builds `brocred_api` for the [bronze](https://github.com/wlejon/bronze)
runtime. bronze (with brass) resolves like brodbus: `../bronze` beside the top-level project,
else the pinned commit. Set `-DBROCRED_ENABLE_API=OFF` to disable the JavaScript binding.

## Tests & Test Oracles

All tests use standard ctest without external testing frameworks (`tests/check.h`). When an
optional OS service or prerequisite tool is absent, tests exit with status `77` (ctest skip)
and log the reason.

Tests storing credentials in real OS stores (Credential Manager, Keychain, Secret Service)
isolate items with unique prefixes and guarantee cleanup before and after each run via RAII.
When no Secret Service daemon is active, Linux tests run the file keystore against isolated
temporary paths.

### Opt-In Tests

To protect developer workstations against unintended side-effects, sensitive authentication
tests require explicit environment variable opt-in:

| Environment Variable | Target Platform | Description & Safety Precautions |
|---|---|---|
| `BROCRED_TEST_AUTH=1` | Linux, Windows | Enables wrong-password verification attempts against the currently logged-in account in `test_*_verifier`. Because repeated wrong attempts trigger OS account lockout policies (Windows locks after 10 failed attempts; Linux `pam_faillock` after 3), this test is disabled by default. When omitted, verifier tests run only against accounts known not to exist. |
| `BROCRED_TEST_TEMP_KEYCHAIN=1` | macOS | Executes keychain tests against an unlocked temporary keychain made the default for the duration of the test. Necessary for headless or SSH CI sessions where the default login keychain is locked. It temporarily modifies the user's keychain search list and restores it upon completion. |

In CI environments, both `BROCRED_TEST_AUTH=1` and `BROCRED_TEST_TEMP_KEYCHAIN=1` are enabled
on disposable virtual machines.
