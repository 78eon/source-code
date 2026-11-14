#!/usr/bin/env python3
"""Launch the configured API with private configuration and external state mounts."""

import json
import os
import re
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def private_path(value, *, directory=False):
    path = Path(value)
    if (not path.is_absolute() or ".." in path.parts
            or any(p.is_symlink() for p in (path, *path.parents))):
        raise ValueError("Workspace paths must be absolute and must not traverse symlinks")
    info = path.stat()
    correct_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not correct_type or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Workspace files/directories must be owner-only and owned by the operator")
    # Podman volume syntax cannot represent colons or newlines safely here.
    if any(c in str(path) for c in (":", "\n", "\r")):
        raise ValueError("Unsupported workspace mount path")
    return path


def durable_path(path):
    return not any(path.is_relative_to(root) for root in map(Path, ("/tmp", "/var/tmp", "/run")))


def workspace_paths(env, *, live=False):
    if not env.get("SECURITY_RL_WORKSPACE_CONFIG"):
        raise ValueError("Set SECURITY_RL_WORKSPACE_CONFIG to a private absolute JSON file")
    if not env.get("SECURITY_RL_WORKSPACE_STATE_DIRECTORY"):
        raise ValueError("Set SECURITY_RL_WORKSPACE_STATE_DIRECTORY to a private directory")
    config = private_path(env["SECURITY_RL_WORKSPACE_CONFIG"])
    config_root = private_path(str(config.parent), directory=True)
    state = private_path(env["SECURITY_RL_WORKSPACE_STATE_DIRECTORY"], directory=True)
    if not state.stat().st_mode & stat.S_IWUSR or not os.access(state, os.W_OK | os.X_OK):
        raise ValueError("Workspace state directory must be writable and searchable")
    if any((p / ".git").exists() for p in (state, *state.parents)):
        raise ValueError("Workspace state must be outside Git checkouts")
    if state.is_relative_to(ROOT) or config_root.is_relative_to(ROOT):
        raise ValueError("Workspace configuration and state must be outside the repository")
    if config_root.is_relative_to(state) or (not live and state.is_relative_to(config_root)):
        raise ValueError("Workspace configuration and state directories must be separate")
    if config.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("Workspace configuration exceeds size limit")
    document = json.loads(config.read_text())
    if not isinstance(document, dict):
        raise ValueError("Workspace configuration must be an object")
    if document.get("offline_processing_enabled") is True:
        if document.get("state_directory") != str(state):
            raise ValueError("Configured state_directory must match the explicit state mount")
    references = [
        document[k] for k in ("attack_snapshot", "vulnerability_snapshot") if document.get(k)
    ]
    for approval in document.get("approvals", []):
        references.extend(approval[k] for k in ("scope_file", "authorization_file"))
    for reference in references:
        if not private_path(reference).is_relative_to(config_root):
            raise ValueError("Referenced files must be inside the configuration directory")
    if live and not all(durable_path(path) for path in (state, config_root)):
        raise ValueError("LIVE_LAB requires durable configuration/state outside temporary roots")
    return config_root, state, document


def command(env, *, live=False):
    if len(env.get("SECURITY_RL_API_TOKEN", "")) < 32:
        raise ValueError("Set SECURITY_RL_API_TOKEN (32+ characters)")
    config_root, state, _ = workspace_paths(env, live=live)
    network = "host"
    image = "localhost/security-rl-desktop-api:dev"
    if live:
        anchor = env.get("SECURITY_RL_LAB_NETWORK_CONTAINER", "")
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", anchor):
            raise ValueError("Select an explicit isolated collector network namespace container")
        network = "container:" + anchor
        image = "localhost/security-rl-controlled-collector:dev"
    return [
        "podman", "run", "--rm", "--pull", "never", "--network", network,
        "--userns", "keep-id", "--user", f"{os.getuid()}:{os.getgid()}",
        "--read-only", "--tmpfs", "/tmp:rw,mode=1777",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "-e", "SECURITY_RL_REQUIRE_REPORT_APPROVAL=1",
        "-e", "SECURITY_RL_API_TOKEN", "-e", "SECURITY_RL_WORKSPACE_CONFIG",
        "-e", "POSTGRES_HOST", "-e", "POSTGRES_PORT", "-e", "POSTGRES_USER",
        "-e", "POSTGRES_PASSWORD", "-e", "POSTGRES_DB",
        "-e", "NEO4J_URI", "-e", "NEO4J_USER", "-e", "NEO4J_PASSWORD",
        "-e", "SECURITY_RL_ANALYST_REPORT_IDS",
        "-v", f"{ROOT / 'src'}:/app/src:ro",
        "-v", f"{ROOT / 'configs/catalogues'}:/app/configs/catalogues:ro",
        "-v", f"{config_root}:{config_root}:ro",
        "-v", f"{state}:{state}:rw",
        image,
        "uvicorn", "rlredteam.api.workspace_runtime:create_configured_app", "--factory",
        "--host", "127.0.0.1", "--port", "8765",
    ]


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live-lab", action="store_true")
    args = parser.parse_args()
    try:
        argv = command(os.environ, live=args.live_lab)
    except (OSError, ValueError, TypeError, KeyError):
        # JSON/parser exceptions can contain private file contents. Never print them.
        print(
            "Workspace launch blocked: check token, private configuration and external state paths",
            file=sys.stderr,
        )
        return 1
    os.execvp(argv[0], argv)


if __name__ == "__main__":
    raise SystemExit(main())
