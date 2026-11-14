#!/usr/bin/env python3
"""Non-destructive host preflight. Never reads .env or starts containers."""

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def configuration_checks():
    checks = {}
    for field in (
        "POSTGRES_USER",
        "POSTGRES_PASSWORD",
        "POSTGRES_DB",
        "NEO4J_USER",
        "NEO4J_PASSWORD",
    ):
        checks[field + "_configured"] = bool(os.environ.get(field))
    port = os.environ.get("POSTGRES_PORT", "5433")
    checks["postgres_port_valid"] = port.isdigit() and 1 <= int(port) <= 65535
    network = os.environ.get("RLREDTEAM_NETWORK", "security-rl-development-internal")
    checks["network_name"] = bool(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}", network))
    return checks


def run(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=45)


def wait_services(project, timeout=45):
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}", project):
        raise ValueError("invalid project identity")
    deadline = time.monotonic() + timeout
    while True:
        states = {}
        for service in ("postgres", "neo4j"):
            result = run(
                [
                    "podman",
                    "ps",
                    "-a",
                    "--filter",
                    "label=com.docker.compose.project=" + project,
                    "--filter",
                    "label=com.docker.compose.service=" + service,
                    "--format",
                    "{{.ID}}",
                ]
            )
            ids = result.stdout.split()
            if result.returncode or len(ids) != 1:
                states[service] = "MISSING_OR_AMBIGUOUS"
                continue
            health = run(["podman", "inspect", "--format", "{{.State.Health.Status}}", ids[0]])
            state = health.stdout.strip()
            states[service] = state if state in {"healthy", "starting", "unhealthy"} else "UNKNOWN"
        ready = all(state == "healthy" for state in states.values())
        if ready or time.monotonic() >= deadline:
            return {
                "overall": "READY" if ready else "BLOCKED",
                "services": states,
                "read_only": True,
            }
        time.sleep(1)


def inspect(root=ROOT, output=None):
    checks = configuration_checks()
    for name in ("podman", "make"):
        checks[name] = shutil.which(name) is not None
    checks["host_python"] = sys.version_info >= (3, 11)
    for name in (
        "compose.analytical.yml",
        "scripts/analytical_runtime.py",
        "src/rlredteam/storage/analytical_migration.sql",
        "desktop/package-lock.json",
    ):
        checks[name] = (root / name).is_file()
    checks["runtime_output"] = output is None or (
        Path(output).is_dir()
        and os.access(output, os.W_OK)
        and bool(Path(output).stat().st_mode & 0o222)
    )
    network = os.environ.get("RLREDTEAM_NETWORK", "security-rl-development-internal")
    checks["network_name"] = bool(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}", network))
    for port in (5433, 7474, 7687, 8765):
        with socket.socket() as sock:
            checks[f"port_{port}_free"] = sock.connect_ex(("127.0.0.1", port)) != 0
    for field in (
        "POSTGRES_USER",
        "POSTGRES_PASSWORD",
        "POSTGRES_DB",
        "NEO4J_USER",
        "NEO4J_PASSWORD",
    ):
        checks[field + "_configured"] = bool(os.environ.get(field))
    if checks["podman"]:
        checks["podman_ready"] = run(["podman", "info", "--format", "json"]).returncode == 0
        checks["compose_provider"] = run(["podman", "compose", "version"]).returncode == 0
        checks["network_exists"] = run(["podman", "network", "exists", network]).returncode == 0
        checks["runtime_image"] = (
            run(["podman", "image", "exists", "localhost/security-rl-desktop-api:dev"]).returncode
            == 0
        )
    boundary = run([sys.executable, "-B", str(root / "scripts/verify_registered_boundary.py")])
    try:
        result = json.loads(boundary.stdout)
        checks["registered_boundary"] = boundary.returncode == 0 and result["status"] == "PASS"
        checks["heldout_locked"] = result["held_out_executed"] is False
    except (KeyError, ValueError):
        checks["registered_boundary"] = checks["heldout_locked"] = False
    # No host chmod assertion: the owner can write there. Only runtime RO mounts
    # enforce read-only access; report that boundary honestly.
    return {
        "overall": "READY" if all(checks.values()) else "BLOCKED",
        "checks": checks,
        "protected_mount_policy": "source/evidence mounts must be RO; host ownership unchanged",
        "network": network,
        "read_only": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--configuration-only", action="store_true")
    parser.add_argument("--wait-services", action="store_true")
    parser.add_argument("--project", default="security-rl-development")
    args = parser.parse_args()
    try:
        if args.wait_services:
            result = wait_services(args.project)
        elif args.configuration_only:
            checks = configuration_checks()
            result = {
                "overall": "READY" if all(checks.values()) else "BLOCKED",
                "checks": checks,
                "read_only": True,
            }
        else:
            result = inspect(output=args.output)
    except Exception:
        result = {"overall": "BLOCKED", "error": "Preflight command failed; no credentials emitted"}
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["overall"] == "READY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
