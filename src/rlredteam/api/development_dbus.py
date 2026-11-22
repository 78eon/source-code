"""UID translation for Secret Service in the rootless development container only.

The host bus verifies the claimed UID against SO_PEERCRED in its own namespace.
Container UID 0 maps to the host user, but Jeepney otherwise claims the inner UID.
"""

import os
import sys
from contextlib import contextmanager
from threading import RLock

_authentication_lock = RLock()


@contextmanager
def host_uid_authentication():
    uid = os.environ.get("SECURITY_RL_DBUS_AUTH_UID")
    if (uid is None or getattr(sys, "frozen", False)
            or os.environ.get("SECURITY_RL_USE_LOCAL_CONFIG") != "1"):
        yield
        return
    if not uid.isascii() or not uid.isdecimal() or len(uid) > 10 or int(uid) >= 2**32 - 1:
        raise ValueError("Invalid development D-Bus UID")
    import jeepney.auth

    with _authentication_lock:
        original = jeepney.auth.make_auth_external
        # Scoped to the CLI credential operation. No authentication bypass:
        # the server rejects a UID that differs from the kernel peer identity.
        jeepney.auth.make_auth_external = lambda: (
            b"AUTH EXTERNAL " + str(int(uid)).encode("ascii").hex().encode("ascii") + b"\r\n"
        )
        try:
            yield
        finally:
            jeepney.auth.make_auth_external = original
