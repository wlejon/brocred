# brocred

[![CI](https://github.com/wlejon/brocred/actions/workflows/ci.yml/badge.svg)](https://github.com/wlejon/brocred/actions/workflows/ci.yml)

Cross-platform credential management, secret storage, lock-screen password verification, and biometric capability detection. A standalone C++20 library with zero external dependencies on bro or bronze, its own CMake build, and comprehensive ctest test suites.

## Overview & Architecture

`brocred` provides native system credential management following the same architectural patterns as `brosys`:
- **Thread Safety & Async Draining**: Asynchronous calls push events into a lock-free/thread-safe `MessageQueue<T>` (`include/brocred/event_queue.h`). The host drains queued events on its own loop via an optional wake hook without blocking callbacks.
- **Honest Capability Reporting**: No mocks in public APIs; native backends report true underlying capabilities or graceful degraded fallbacks.
- **Strict File Decomposition**: All files are strictly under 1,000 LOC.
- **Real OS Test Oracles**: Automated ctests invoke real operating system utilities (`cmdkey.exe`, macOS `/usr/bin/security`, Linux `secret-tool`, or an isolated private D-Bus daemon) and assert mutual read/write interoperability with zero machine leftovers (unconditional cleanup).

```
include/brocred/
  brocred.h         Umbrella header
  common.h          Result, Availability, BiometricAvailability, BiometricType, stream operators
  credential.h      Credential, CredentialMetadata
  event_queue.h     MessageQueue<T> (thread-safe, push/drain/wait_for/wake)
  events.h          CredentialChangedEvent, AuthPromptEvent, BiometricStatusEvent, EventQueue
  features.h        compiled_features(): which optional integrations this build has
  storage.h         CredentialStore interface & global default store accessors
  verifier.h        verify_password, verify_password_async
  biometrics.h      get_biometric_capabilities, check_biometrics_async
  polkit_agent.h    PolkitAgent: a PolicyKit authentication agent (Linux)
  secret_service.h  SecretServiceProvider: serves org.freedesktop.secrets from a CredentialStore (Linux)
```

## Backend Implementation Matrix

| Capability | Windows | macOS | Linux |
|---|---|---|---|
| **Secret Storage** | Windows Credential Manager (`CredWriteW`, `CredReadW`, `CredDeleteW`, `CredEnumerateW`) | Apple Keychain Services (`SecItemAdd`, `SecItemCopyMatching`, `SecItemDelete`, `SecItemUpdate`) | FreeDesktop Secret Service over D-Bus (`org.freedesktop.secrets` via `sd-bus`) with automatic fallback to `FileKeystore` |
| **Password Verification** | Win32 `LogonUserW` (`LOGON32_LOGON_NETWORK` / `LOGON32_LOGON_INTERACTIVE`) | OpenDirectory (`ODSession`, `ODNode`, `ODRecordVerifyPassword`) | Linux PAM (`pam_start`, `pam_authenticate`, conversation handler) |
| **Biometrics Detection** | Windows Hello (`UserConsentVerifier` WinRT) & Windows Biometric Framework (`WinBioEnumBiometricUnits`) | LocalAuthentication (`LAContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics:`) | `fprintd` over system D-Bus (`net.reactivated.Fprint.Manager` via `sd-bus`) |
| **Test Oracles** | `cmdkey.exe /generic:... /user:... /pass:...` | `/usr/bin/security add-generic-password` / `find-generic-password` | Isolated private `dbus-daemon` mock & `secret-tool` |

## Secret Storage Backends

### Windows Credential Manager
- Targets stored with format `service:account` or custom target names.
- Automatic UTF-16LE / UTF-8 blob decoding for seamless compatibility with third-party Windows apps and `cmdkey`.
- Custom key-value attributes stored via `CREDENTIAL_ATTRIBUTEW`.

### macOS Keychain
- Generic passwords stored in macOS Keychain (`kSecClassGenericPassword`).
- Metadata and custom attributes serialized as structured JSON in `kSecAttrGeneric`.
- Non-interactive test isolation supports custom keychain search lists (`SecKeychainCopySearchList`, `kSecMatchSearchList`).

### Linux Secret Service & Fallback Keystore
- Connects directly to the D-Bus session bus using `sd-bus` to communicate with `org.freedesktop.secrets` (GNOME Keyring, KWallet).
- Detects bus ownership (`has_owner`) and enforces strict 2-second call timeouts to prevent hangs in headless/SSH environments.
- When no Secret Service daemon is registered, cleanly falls back to `FileKeystore` (`~/.local/share/brocred/credentials.store` with POSIX `0600` permissions and atomic `.tmp` writes) or `MemoryKeystore`.

## Desktop agents (Linux)

For a desktop shell that is its own session, brocred also provides the two
services a Linux session expects someone to run:

- **`PolkitAgent`** registers as the PolicyKit authentication agent
  (`org.freedesktop.PolicyKit1.AuthenticationAgent`), hands each
  `BeginAuthentication` to your handler (the shell's password prompt) and
  completes it with the authority.
- **`SecretServiceProvider`** serves `org.freedesktop.secrets` (collections,
  items, `plain` and `dh-ietf1024-sha256-aes128-cbc-pkcs7` sessions) backed by
  any `CredentialStore`, so `secret-tool`, libsecret and browsers can store
  secrets in it.

Both need sd-bus, and the encrypted session needs OpenSSL's libcrypto. On
Windows and macOS (neither has PolicyKit or the Secret Service), and on Linux
without sd-bus, the factories still return objects whose `start()` fails with
the reason; `compiled_features().polkit_agent` and `.secret_service_provider`
report it up front. The Linux tests run both on private `dbus-daemon` buses
and call them over the wire with sd-bus, the way a client would
(`test_secret_service`, `test_polkit_agent`, `test_linux_dbus_client`).

## Lock-Screen Password Verification

`brocred` verifies local user passwords non-destructively:
- **Windows**: `LogonUserW` validates credentials without needing elevated Administrator privileges. Distinguishes incorrect passwords (`ERROR_LOGON_FAILURE`) from locked or expired accounts.
- **macOS**: `ODRecordVerifyPassword` checks passwords through macOS OpenDirectory directly without spawning GUI prompts.
- **Linux**: PAM conversation using `/etc/pam.d/login` or `/etc/pam.d/system-auth`.

## Biometric Capabilities

Returns biometric availability (`Available`, `NotEnrolled`, `NotSupported`, `PermissionDenied`):
- **Windows**: Detects whether Windows Hello Facial Recognition or Fingerprint sensors are present and configured.
- **macOS**: Identifies Touch ID or Face ID support via `LAContext`.
- **Linux**: Detects enrolled fingerprint sensors via `fprintd` system D-Bus service.

## Building & Testing

There are no sibling repos to fetch: brocred links only the OS.

### Prerequisites
- **C++20** compliant compiler:
  - Windows: MSVC 2022+
  - Linux: GCC 12+ or Clang 15+; optionally `libsystemd-dev` / `systemd-libs` with `libssl-dev` / `openssl`, and `libpam0g-dev` / `pam`
  - macOS: Xcode 14+ / Apple Clang
- **CMake 3.24+**

### Optional Linux integrations

| CMake option | Needs | Without it |
|---|---|---|
| `BROCRED_WITH_SDBUS` (`AUTO`/`ON`/`OFF`, default `AUTO`) | libsystemd >= 246 (sd-bus), and OpenSSL libcrypto for the Secret Service provider's encrypted sessions | `CredentialStore` (Auto) uses the file keystore; `BackendType::System` fails with an explanation; biometrics report `Unknown` (fprintd cannot be asked); `PolkitAgent` and `SecretServiceProvider` report themselves unavailable |
| `BROCRED_WITH_PAM` (`AUTO`/`ON`/`OFF`, default `AUTO`) | PAM headers + library | `verify_password()` fails with an explanatory error |

`AUTO` uses an integration when its development files are found, `ON` makes a
missing one a configure error. `brocred::compiled_features()`
(`brocred/features.h`) reports what a build contains; the runtime APIs
(`backend_name()`, `get_biometric_capabilities()`) report whether the
service is actually running.

### Windows (MSVC)
```powershell
cmake -B build -S .
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

### Linux (GCC / Clang)
```bash
cmake -B build-release -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build-release
ctest --test-dir build-release --output-on-failure
```

### macOS (Apple Clang)
```bash
cmake -B build-release -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build-release
ctest --test-dir build-release --output-on-failure
```

## Test Harness & Oracles
- Tests use standard ctest without third-party frameworks (`tests/check.h`).
- Tests exit with return code `77` when an environment prerequisite (e.g. absent CLI tool or headless environment without biometrics hardware) is honestly not present.
- Tests that store credentials in the real OS store (Credential Manager, login keychain, Secret Service keyring) delete their items before starting and again on every exit path (RAII). When no Secret Service runs, the Linux tests point the file keystore at a private temporary file instead of `~/.local/share`.

### Opt-in tests

A plain `ctest` changes nothing a user would notice beyond those scoped test items:

| Variable | Enables |
|---|---|
| `BROCRED_TEST_AUTH=1` | Wrong-password attempts against the logged-in account in `test_*_verifier`. They count toward account-lockout policies (Windows 11 locks after 10 by default; `pam_faillock` after 3 on some distributions) and are logged as failed logons. By default only an account that does not exist is tried. |
| `BROCRED_TEST_TEMP_KEYCHAIN=1` (macOS) | Runs the keychain tests against an unlocked temporary keychain made the default for the test's duration, for sessions whose login keychain is locked (SSH on a build Mac). It rewrites the user's keychain search list while it runs and restores it afterwards; a test killed mid-run leaves the preferences pointing at a deleted keychain. Without it, a locked login keychain makes those tests skip. |
