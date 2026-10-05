# brocred

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
  storage.h         CredentialStore interface & global default store accessors
  verifier.h        verify_password, verify_password_async
  biometrics.h      get_biometric_capabilities, check_biometrics_async
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

### Prerequisites
- **C++20** compliant compiler:
  - Windows: MSVC 2022+
  - Linux: GCC 12+ or Clang 15+, `libsystemd-dev` / `systemd-libs`, `libpam0g-dev` / `pam`
  - macOS: Xcode 14+ / Apple Clang
- **CMake 3.20+**

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
- Every test guarantees zero leftover credentials, files, or background daemons.
