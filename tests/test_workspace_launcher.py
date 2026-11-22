"""Configured launcher contracts; no containers or network are started."""

import importlib.util
import json
import os
import secrets
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "workspace_launcher", "scripts/workspace_api_launcher.py"
)
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)


@pytest.fixture
def configured(tmp_path):
    config_root = tmp_path / "private config"
    config_root.mkdir(mode=0o700)
    state = tmp_path / "private state"
    state.mkdir(mode=0o700)
    config = config_root / "workspace.json"
    config.write_text(json.dumps({"version": 1, "state_directory": str(state)}))
    config.chmod(0o600)
    return {
        "SECURITY_RL_API_TOKEN": secrets.token_hex(32),
        "SECURITY_RL_WORKSPACE_CONFIG": str(config),
        "SECURITY_RL_WORKSPACE_STATE_DIRECTORY": str(state),
    }


def test_launcher_factory_mounts_binding_and_hardening(configured):
    argv = launcher.command(configured)
    assert argv[-7:] == [
        "uvicorn", "rlredteam.api.workspace_runtime:create_configured_app", "--factory",
        "--host", "127.0.0.1", "--port", "8765",
    ]
    assert argv[argv.index("--userns") + 1] == "keep-id"
    assert argv[argv.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert argv[argv.index("--security-opt") + 1] == "no-new-privileges"
    assert "--read-only" in argv
    mounts = [argv[i + 1] for i, value in enumerate(argv) if value == "-v"]
    config_root = str(Path(configured["SECURITY_RL_WORKSPACE_CONFIG"]).parent)
    state = configured["SECURITY_RL_WORKSPACE_STATE_DIRECTORY"]
    assert f"{config_root}:{config_root}:ro" in mounts
    assert f"{state}:{state}:rw" in mounts
    assert all(m.endswith(":ro") for m in mounts if not m.startswith(state + ":"))
    assert any(m.endswith(":/app/src:ro") for m in mounts)
    assert configured["SECURITY_RL_API_TOKEN"] not in " ".join(argv)
    assert "SECURITY_RL_WORKSPACE_CONFIG" in argv
    assert "--privileged" not in argv


@pytest.mark.parametrize("key", [
    "SECURITY_RL_API_TOKEN",
    "SECURITY_RL_WORKSPACE_CONFIG",
    "SECURITY_RL_WORKSPACE_STATE_DIRECTORY",
])
def test_missing_required_input_blocks_before_podman(configured, key):
    configured.pop(key)
    with pytest.raises(ValueError):
        launcher.command(configured)


def test_short_token_rejected(configured):
    configured["SECURITY_RL_API_TOKEN"] = "short"
    with pytest.raises(ValueError, match="32"):
        launcher.command(configured)


def test_missing_or_public_config_rejected(configured):
    path = Path(configured["SECURITY_RL_WORKSPACE_CONFIG"])
    path.chmod(0o644)
    with pytest.raises(ValueError, match="owner-only"):
        launcher.command(configured)
    configured["SECURITY_RL_WORKSPACE_CONFIG"] += ".missing"
    with pytest.raises(OSError):
        launcher.command(configured)


def test_unwritable_state_directory_is_rejected(configured):
    state = Path(configured["SECURITY_RL_WORKSPACE_STATE_DIRECTORY"])
    state.chmod(0o500)
    try:
        with pytest.raises(ValueError, match="writable"):
            launcher.command(configured)
    finally:
        state.chmod(0o700)


def test_state_inside_checkout_or_config_rejected(configured, tmp_path):
    (tmp_path / ".git").mkdir()
    with pytest.raises(ValueError, match="outside Git"):
        launcher.command(configured)
    (tmp_path / ".git").rmdir()
    state = Path(configured["SECURITY_RL_WORKSPACE_CONFIG"]).parent / "state"
    state.mkdir(mode=0o700)
    configured["SECURITY_RL_WORKSPACE_STATE_DIRECTORY"] = str(state)
    with pytest.raises(ValueError, match="separate"):
        launcher.command(configured)


def test_state_must_match_document_and_references_must_be_mounted(configured, tmp_path):
    path = Path(configured["SECURITY_RL_WORKSPACE_CONFIG"])
    path.write_text(json.dumps({"offline_processing_enabled": True, "state_directory": "/wrong"}))
    with pytest.raises(ValueError, match="match"):
        launcher.command(configured)
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    outside.chmod(0o600)
    path.write_text(json.dumps({"attack_snapshot": str(outside)}))
    with pytest.raises(ValueError, match="inside the configuration"):
        launcher.command(configured)


def test_symlinks_and_parent_traversal_are_rejected(configured, tmp_path):
    original = Path(configured["SECURITY_RL_WORKSPACE_CONFIG"])
    link = tmp_path / "linked.json"
    link.symlink_to(original)
    configured["SECURITY_RL_WORKSPACE_CONFIG"] = str(link)
    with pytest.raises(ValueError, match="symlinks"):
        launcher.command(configured)
    configured["SECURITY_RL_WORKSPACE_CONFIG"] = str(original.parent / ".." / original.name)
    with pytest.raises(ValueError, match="absolute"):
        launcher.command(configured)


def test_invalid_private_config_logs_no_contents_or_token(configured):
    marker = secrets.token_hex(32)
    Path(configured["SECURITY_RL_WORKSPACE_CONFIG"]).write_text(marker)
    result = subprocess.run(
        [sys.executable, "-B", "scripts/workspace_api_launcher.py"],
        env=dict(os.environ, **configured), capture_output=True, text=True,
    )
    assert result.returncode == 1
    assert "Workspace launch blocked" in result.stderr
    assert marker not in result.stderr + result.stdout
    assert configured["SECURITY_RL_API_TOKEN"] not in result.stderr + result.stdout


def test_make_keeps_basic_target_and_adds_explicit_workspace_target():
    basic = subprocess.check_output(["make", "-n", "api-dev"], text=True)
    workspace = subprocess.check_output(["make", "-n", "api-workspace-dev"], text=True)
    assert "uvicorn rlredteam.api.app:app" in basic
    assert "python3 -B scripts/workspace_api_launcher.py" in workspace
    assert "build" not in workspace and "services-up" not in workspace


def test_live_launcher_selects_only_collector_image_and_explicit_namespace(configured, monkeypatch):
    monkeypatch.setattr(launcher, "durable_path", lambda path: True)
    with pytest.raises(ValueError, match="namespace"):
        launcher.command(configured, live=True)
    configured["SECURITY_RL_LAB_NETWORK_CONTAINER"] = "operator-isolated-anchor"
    argv = launcher.command(configured, live=True)
    assert "localhost/security-rl-controlled-collector:dev" in argv
    assert argv[argv.index("--network") + 1] == "container:operator-isolated-anchor"
    assert argv[argv.index("--host") + 1] == "127.0.0.1"
    assert "--privileged" not in argv and "host" not in argv
    assert argv[argv.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"


def test_live_launcher_rejects_temporary_operational_storage(configured):
    configured["SECURITY_RL_LAB_NETWORK_CONTAINER"] = "operator-isolated-anchor"
    with pytest.raises(ValueError, match="durable"):
        launcher.command(configured, live=True)


def test_research_archive_mount_is_read_only_without_relabel(configured, tmp_path):
    archive = tmp_path / "research archive"
    archive.mkdir()
    (archive / "protocol_manifest.json").write_text("{}")
    configured["SECURITY_RL_REGISTERED_CAMPAIGN"] = str(archive)
    argv = launcher.command(configured)
    assert f"{archive}:/app/registered-campaign:ro" in argv
    assert "SECURITY_RL_REGISTERED_CAMPAIGN=/app/registered-campaign" in argv
    assert not any("registered-campaign:ro," in value for value in argv)


def test_desktop_dev_avoids_keep_id_and_preserves_mounts_and_hardening(tmp_path):
    # Dry-run only: no containers, X11 connection or database operations.
    archive = tmp_path / "registered metadata"
    archive.mkdir()
    (archive / "protocol_manifest.json").write_text("{}")
    output = subprocess.check_output(
        ["make", "-n", "desktop-dev"], text=True,
        env=dict(os.environ, SECURITY_RL_REGISTERED_CAMPAIGN=str(archive)),
    )
    command = output[output.index("podman run "):].replace("\\\n", " ")
    argv = shlex.split(command)
    assert "--userns" not in argv and not any(arg.startswith("--userns=") for arg in argv)
    assert argv[argv.index("--user") + 1] == "0:0"
    assert "--privileged" not in argv
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert argv[argv.index("--security-opt") + 1] == "no-new-privileges"
    mounts = [argv[i + 1] for i, value in enumerate(argv) if value == "-v"]
    assert f"{archive}:/app/registered-campaign:ro" in mounts
    assert "$XAUTHORITY:/tmp/desktop.xauth:ro" in mounts
    assert "/tmp/.X11-unix:/tmp/.X11-unix:ro" in mounts
    assert any(m.endswith(":/app/desktop:rw,z") for m in mounts)
    assert not any(m.endswith(":U") or ",U" in m for m in mounts)
    environment = [argv[i + 1] for i, value in enumerate(argv) if value == "-e"]
    for key in ("DISPLAY", "POSTGRES_HOST", "POSTGRES_PORT", "POSTGRES_USER",
                "POSTGRES_PASSWORD", "POSTGRES_DB", "NEO4J_USER",
                "NEO4J_PASSWORD", "SECURITY_RL_ANALYST_REPORT_IDS"):
        assert key in environment
    assert "XAUTHORITY=/tmp/desktop.xauth" in environment
    assert "NEO4J_URI=bolt://127.0.0.1:7687" in environment
    assert "XDG_CONFIG_HOME=/app/desktop-config" in environment
    assert "${XDG_CONFIG_HOME:-$HOME/.config}/org.securityrl.analyst:/app/desktop-config/org.securityrl.analyst:rw" in mounts
    assert "DBUS_SESSION_BUS_ADDRESS" in environment
    assert "XDG_RUNTIME_DIR" in environment
    assert 'SECURITY_RL_DBUS_AUTH_UID=$(id -u)' in environment
    assert "$XDG_RUNTIME_DIR/bus:$XDG_RUNTIME_DIR/bus:ro" in mounts
    assert all(not mount.startswith("$XDG_RUNTIME_DIR:") for mount in mounts)
    assert argv[argv.index("--tmpfs") + 1] == "$XDG_RUNTIME_DIR:rw,mode=700"
    assert "SECURITY_RL_REGISTERED_CAMPAIGN=/app/registered-campaign" in environment
    assert argv[-8:] == ["localhost/security-rl-desktop-builder:dev", "npm", "run", "tauri", "--", "dev",
                         "--config", "src-tauri/tauri.dev.conf.json"]


def test_tauri_dev_overlay_omits_packaged_runtime_but_release_keeps_it():
    base = json.loads(Path("desktop/src-tauri/tauri.conf.json").read_text())
    dev = json.loads(Path("desktop/src-tauri/tauri.dev.conf.json").read_text())
    assert dev["bundle"] == {"resources": []}
    assert set(dev) == {"$schema", "bundle"}
    assert base["bundle"]["resources"] == {
        "runtime/security-rl-api/": "runtime/security-rl-api/"
    }
    package = subprocess.check_output(["make", "-n", "desktop-package"], text=True)
    assert "pyinstaller" in package
    assert "--distpath src-tauri/runtime" in package
    assert "tauri.dev.conf.json" not in package
    assert "verify_bundle.py" in package


def test_development_builder_provides_existing_backend_python():
    containerfile = Path("desktop/Containerfile").read_text()
    assert "python3 -m venv /opt/analyst-python" in containerfile
    assert "SECURITY_RL_BACKEND_PYTHON=/opt/analyst-python/bin/python" in containerfile
    assert "PYTHONPATH=/app/src" in containerfile


def test_host_network_desktop_does_not_inherit_compose_neo4j_uri():
    output = subprocess.check_output(["make", "-n", "desktop-dev"], text=True,
                                    env=dict(os.environ, NEO4J_URI="bolt://neo4j:7687"))
    assert '-e NEO4J_URI="bolt://127.0.0.1:7687"' in output
    assert "bolt://neo4j:7687" not in output
    custom = subprocess.check_output(["make", "-n", "desktop-dev", "DESKTOP_NEO4J_URI=bolt://127.0.0.1:17687"], text=True)
    assert '-e NEO4J_URI="bolt://127.0.0.1:17687"' in custom
