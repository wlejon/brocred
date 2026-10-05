#!/usr/bin/env bash
# Run a command with an unlocked gnome-keyring Secret Service on the current
# D-Bus session bus (start the session with dbus-run-session first).
#
# --unlock reads the login keyring's password from stdin, creating the keyring
# when it does not exist, which is what a fresh CI home directory needs; the
# password only has to be consistent within this one run. The daemon prints
# the variables its clients need (GNOME_KEYRING_CONTROL, ...), so they are
# exported before the command runs.
set -euo pipefail

if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]; then
    echo "with-keyring.sh: no session bus; run it under dbus-run-session" >&2
    exit 1
fi

eval "$(printf 'brocred-ci' | gnome-keyring-daemon --unlock --components=secrets | sed 's/^/export /')"

# The daemon registers org.freedesktop.secrets asynchronously; wait for it so
# the first test does not race the name onto the bus.
for _ in $(seq 50); do
    if busctl --user status org.freedesktop.secrets >/dev/null 2>&1 \
       || dbus-send --session --print-reply --dest=org.freedesktop.DBus / \
            org.freedesktop.DBus.GetNameOwner string:org.freedesktop.secrets >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

exec "$@"
