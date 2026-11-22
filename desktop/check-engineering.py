"""Run the synthetic browser flow inside the network-disabled desktop image.

Uses disposable local simulation state and loopback only; no database, keyring,
registered campaign or external targets are configured. Run with --network none.
"""

import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.request


def main():
    with tempfile.TemporaryDirectory(prefix="rlrt-engineering-e2e-") as state:
        env = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("POSTGRES_", "NEO4J_", "PG"))
            and key not in {"SECURITY_RL_REGISTERED_CAMPAIGN", "SECURITY_RL_USE_LOCAL_CONFIG",
                            "SECURITY_RL_WORKSPACE_CONFIG", "SECURITY_RL_ANALYST_REPORT_IDS"}
        }
        env.update(SECURITY_RL_API_TOKEN=secrets.token_hex(32),
                   SECURITY_RL_ENGINEERING_SIMULATION_STATE=str(Path(state) / "engineering-simulations"),
                   SECURITY_RL_ENGINEERING_E2E="1", PYTHONDONTWRITEBYTECODE="1")
        server = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "rlredteam.api.app:create_app", "--factory",
             "--host", "127.0.0.1", "--port", "8765", "--no-access-log"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            for _ in range(100):
                if server.poll() is not None:
                    raise RuntimeError("Disposable engineering API exited before readiness")
                try:
                    with urllib.request.urlopen("http://127.0.0.1:8765/api/health", timeout=1):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("Disposable engineering API did not become ready")
            return subprocess.call(
                ["npx", "--no-install", "playwright", "test", "e2e/engineering.spec.ts",
                 "--output=/tmp/engineering-playwright-results"],
                cwd=Path(__file__).parent, env=env,
            )
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()


if __name__ == "__main__":
    raise SystemExit(main())
