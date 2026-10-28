"""Run in the desktop Podman image with an isolated PID/network namespace."""

import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path


def backend_pids():
    result = []
    for path in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            if b"\x00-m\x00rlredteam.api.owned_backend\x00" in path.read_bytes():
                result.append(int(path.parent.name))
        except OSError:
            pass
    return result


assert not backend_pids(), "Smoke test requires an isolated PID namespace"
runtime = Path("/tmp/securityrl-native-runtime")
runtime.mkdir(mode=0o700, exist_ok=True)
env = {
    **os.environ,
    "SECURITY_RL_SMOKE_EXIT_SECONDS": "45",
    "XDG_RUNTIME_DIR": str(runtime),
    "XDG_CACHE_HOME": "/tmp/securityrl-cache",
    "XDG_CONFIG_HOME": "/tmp/securityrl-config",
    "XDG_DATA_HOME": "/tmp/securityrl-data",
}
subprocess.run(
    [env["SECURITY_RL_BACKEND_PYTHON"], "-m", "rlredteam.api.owned_backend", "--config", "save"],
    input=json.dumps(
        {
            "settings": {
                "version": 1,
                "profile": "demo",
                "postgres": None,
                "neo4j": None,
                "report_ids": [],
                "twin_snapshot": None,
            }
        }
    ),
    text=True,
    capture_output=True,
    env=env,
    check=True,
)
process = subprocess.Popen(
    ["xvfb-run", "-a", "dbus-run-session", "--", "src-tauri/target/debug/security-rl-desktop"],
    env=env,
)
try:
    observed = None
    startup_deadline = time.monotonic() + 35
    while time.monotonic() < startup_deadline:
        pids = backend_pids()
        if pids:
            assert len(pids) == 1
            for row in Path("/proc/net/tcp").read_text().splitlines()[1:]:
                columns = row.split()
                address, port = columns[1].split(":")
                if address != "0100007F" or columns[3] != "0A":
                    continue
                try:
                    with urllib.request.urlopen(
                        f"http://127.0.0.1:{int(port,16)}/api/health", timeout=0.3
                    ) as response:
                        health = json.load(response)
                    if health.get("instance") and health.get("read_only"):
                        observed = pids[0]
                        break
                except (OSError, ValueError):
                    pass
        if observed:
            break
        if process.poll() is not None:
            break
        time.sleep(0.1)
    assert observed, f"Native startup failed (exit={process.poll()}, backend PIDs={backend_pids()})"
    assert process.wait(timeout=50) == 0
    assert not backend_pids(), "Owned backend leaked after desktop exit"
    print(
        "NATIVE_SMOKE_PASS: React IPC -> owned loopback backend -> health -> graceful exit; "
        "no leaked child"
    )
finally:
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=10)
