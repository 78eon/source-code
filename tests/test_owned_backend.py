"""Real process lifetime tests; run inside network-disabled Podman."""

import json
import os
import selectors
import subprocess
import sys
import time

import httpx


def launch(runtime):
    env = {**os.environ, "XDG_RUNTIME_DIR": str(runtime)}
    return subprocess.Popen(
        [sys.executable, "-m", "rlredteam.api.owned_backend"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
    )


def test_owned_backend_auth_duplicate_and_eof_shutdown(tmp_path):
    process = launch(tmp_path)
    duplicate = None
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            assert selector.select(timeout=15), "Backend handshake timeout"
        line = process.stdout.readline()
        assert line, process.stderr.read()
        session = json.loads(line)
        assert session["origin"].startswith("http://127.0.0.1:")
        assert len(session["token"]) >= 32
        with httpx.Client(base_url=session["origin"], trust_env=False) as client:
            for _ in range(100):
                try:
                    health = client.get("/api/health")
                    break
                except httpx.ConnectError:
                    time.sleep(0.05)
            assert health.json()["instance"] == session["instance"]
            assert client.get("/api/assets").status_code == 401
            response = client.get(
                "/api/digital-twin/summary", headers={"Authorization": "Bearer " + session["token"]}
            )
            assert response.status_code == 200
            assert session["token"] not in health.text
            duplicate = launch(tmp_path)
            assert duplicate.wait(timeout=15) == 2
            assert client.get("/api/health").status_code == 200
        process.stdin.close()
        assert process.wait(timeout=8) == 0
        assert session["token"] not in process.stderr.read()
        # Lock released: a subsequent desktop can start, with a different token.
        successor = launch(tmp_path)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(successor.stdout, selectors.EVENT_READ)
                assert selector.select(timeout=15)
            assert json.loads(successor.stdout.readline())["token"] != session["token"]
        finally:
            successor.stdin.close()
            successor.wait(timeout=8)
    finally:
        for child in (process, duplicate):
            if child and child.poll() is None:
                child.kill()
                child.wait()
