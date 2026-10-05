---
name: Bug report
about: A secret is stored or read wrongly, a password check gives the wrong answer, biometrics are misreported, or something crashes
labels: bug
---

**If this is a security problem** (a secret written somewhere it should not
be, readable by another user, or left behind), please do not post the details
publicly; open an issue saying only that you have one, and we will arrange a
private channel.

**Area:** secret storage / password verification / biometrics

**Backend in use** (`backend_name()`, and `compiled_features()` on Linux):

**What the OS says** (the oracle: `cmdkey /list`, `security find-generic-password`,
`secret-tool lookup`, the fingerprint settings, ...):

```
```

**What brocred did instead** (the `Result` error, a crash, or the failing
`ctest --output-on-failure` output — paste it, with no real secrets in it):

```
```

**Environment:**
- OS and version; on Linux the desktop and its keyring (gnome-keyring, KWallet, KeePassXC, ...):
- Compiler / toolchain (MSVC / GCC / Clang):
- brocred commit:
