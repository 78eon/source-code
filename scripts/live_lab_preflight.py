#!/usr/bin/env python3
"""Read-only operational preflight. No scanner invocation, approval, or VM mutation."""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.workspace_api_launcher import ROOT, private_path, workspace_paths  # noqa: E402

API_IMAGE = "localhost/security-rl-desktop-api:dev"
COLLECTOR_IMAGE = "localhost/security-rl-controlled-collector:dev"


class PreflightParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("Supply --request and --topology private JSON paths; no extra flags")


def run(argv, timeout=30):
    with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, start_new_session=True) as process:
        try:
            stdout, _ = process.communicate(timeout=timeout)
            return SimpleNamespace(returncode=process.returncode, stdout=stdout)
        except subprocess.TimeoutExpired:
            # Terminate only this read-only probe's newly created process group.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate(timeout=3)
            raise


def inspect(env, request_path, topology_path, *, execute=run):
    reasons = []
    raw_execute = execute

    def execute(argv):
        try:
            return raw_execute(argv)
        except (OSError, subprocess.TimeoutExpired):
            reasons.append("Podman read-only probe unavailable or timed out: " + argv[1])
            return SimpleNamespace(returncode=1, stdout="")
    if len(env.get("SECURITY_RL_API_TOKEN", "")) < 32:
        reasons.append("API not configured: SECURITY_RL_API_TOKEN requires at least 32 characters")
    try:
        config_root, state, _ = workspace_paths(env, live=True)
        request = private_path(request_path)
        topology = private_path(topology_path)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        detail = (
            str(exc)
            if type(exc) is ValueError
            else "Private paths missing, unreadable or malformed"
        )
        return {"status": "BLOCKED", "reasons": [*reasons, detail]}
    for image, expected in ((API_IMAGE, False), (COLLECTOR_IMAGE, True)):
        if execute(["podman", "image", "exists", image]).returncode:
            reasons.append("Required runtime image unavailable: " + image)
            continue
        code = (
            "import shutil; raise SystemExit((shutil.which('nmap') is not None) != "
            + repr(expected)
            + ")"
        )
        probe = execute(
            [
                "podman",
                "run",
                "--rm",
                "--pull",
                "never",
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--entrypoint",
                "python",
                image,
                "-B",
                "-c",
                code,
            ]
        )
        if probe.returncode:
            reasons.append("Nmap binary separation check failed: " + image)
    mounts = [
        "--userns",
        "keep-id",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,mode=1777",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "-e",
        "PYTHONDONTWRITEBYTECODE=1",
        "-e",
        "SECURITY_RL_WORKSPACE_CONFIG",
        "-e",
        "SECURITY_RL_API_TOKEN",
        "-v",
        f"{ROOT / 'src'}:/app/src:ro",
        "-v",
        f"{config_root}:{config_root}:ro",
        "-v",
        f"{state}:{state}:rw",
        "-v",
        f"{request}:{request}:ro",
        "-v",
        f"{topology}:{topology}:ro",
    ]
    for name in (
        "POSTGRES_HOST",
        "POSTGRES_PORT",
        "POSTGRES_USER",
        "POSTGRES_PASSWORD",
        "POSTGRES_DB",
        "NEO4J_URI",
        "NEO4J_USER",
        "NEO4J_PASSWORD",
    ):
        mounts.extend(("-e", name))

    def check(mode, network):
        result = execute(
            [
                "podman",
                "run",
                "--rm",
                "--pull",
                "never",
                "--network",
                network,
                *mounts,
                "--entrypoint",
                "python",
                COLLECTOR_IMAGE,
                "-B",
                "-m",
                "rlredteam.api.live_lab_readiness",
                mode,
                "--request",
                str(request),
                "--topology",
                str(topology),
            ]
        )
        try:
            document = json.loads(result.stdout)
            if document["status"] not in ("READY", "BLOCKED"):
                raise ValueError("invalid result")
            reasons.extend(document["reasons"])
            if result.returncode and not document["reasons"]:
                raise ValueError("missing failure reasons")
        except (ValueError, TypeError, KeyError):
            reasons.append("Read-only " + mode + " probe failed; raw diagnostics suppressed")

    check("configuration", "none")
    anchor = env.get("SECURITY_RL_LAB_NETWORK_CONTAINER", "")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", anchor):
        reasons.append(
            "No verified lab-restricted Podman network namespace; "
            "SECURITY_RL_LAB_NETWORK_CONTAINER is unset"
        )
    else:
        running = execute(["podman", "inspect", "--format", "{{.State.Running}}", anchor])
        if running.returncode or running.stdout.strip() != "true":
            reasons.append("Selected isolated network namespace container is not running")
        else:
            check("route", "container:" + anchor)
            check("dependencies", "container:" + anchor)
    return {"status": "BLOCKED" if reasons else "READY", "reasons": sorted(set(reasons))}


def main():
    parser = PreflightParser(description=__doc__)
    parser.add_argument("--request", required=True)
    parser.add_argument("--topology", required=True)
    try:
        args = parser.parse_args()
        result = inspect(os.environ, args.request, args.topology)
    except ValueError:
        result = {"status": "BLOCKED", "reasons": [
            "Supply valid private request/topology paths and supported preflight arguments"
        ]}
    except Exception:
        result = {
            "status": "BLOCKED",
            "reasons": ["Read-only runtime inspection failed; raw diagnostics suppressed"],
        }
    print(json.dumps(result, sort_keys=True))
    return result["status"] != "READY"


if __name__ == "__main__":
    raise SystemExit(main())
