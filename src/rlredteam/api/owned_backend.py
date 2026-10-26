"""Desktop-owned loopback service. Private stdout handshake, stdin-EOF shutdown.

The parent must keep stdin open. Tokens are generated per process and never
written to files or logs. Only Linux desktop development is supported here.
"""

import fcntl
import json
import os
import secrets
import socket
import stat
import sys
import threading
from pathlib import Path

import uvicorn


def main():
    runtime = Path(os.environ.get("XDG_RUNTIME_DIR", "/tmp")) / f"security-rl-{os.getuid()}"
    runtime.mkdir(mode=0o700, exist_ok=True)
    info = runtime.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RuntimeError("Unsafe runtime directory")
    lock = os.open(runtime / "backend.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("A desktop backend is already owned by another application instance", file=sys.stderr)
        os.close(lock)
        return 2
    token = secrets.token_urlsafe(48)
    instance = secrets.token_hex(16)
    os.environ["SECURITY_RL_API_TOKEN"] = token
    os.environ["SECURITY_RL_BACKEND_INSTANCE"] = instance
    from .app import create_app

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        port = listener.getsockname()[1]
        server = uvicorn.Server(
            uvicorn.Config(
                create_app(),
                host="127.0.0.1",
                port=port,
                access_log=False,
                log_level="error",
                timeout_graceful_shutdown=3,
            )
        )

        def parent_lifetime():
            # Only the owning process holds this pipe. Never signal other processes.
            while sys.stdin.buffer.read(1):
                pass
            server.should_exit = True

        threading.Thread(target=parent_lifetime, daemon=True).start()
        print(
            json.dumps(
                {"origin": f"http://127.0.0.1:{port}", "token": token, "instance": instance}
            ),
            flush=True,
        )
        try:
            server.run(sockets=[listener])
        finally:
            os.close(lock)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
