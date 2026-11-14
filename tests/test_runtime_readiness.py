"""Pure operational states and static no-training contracts."""

import ast
import json
from pathlib import Path

import pytest

from rlredteam.application.runtime_readiness import classify

BASE = {
    "postgres": "POSTGRES_READY_WITH_DATA",
    "selected": ["a" * 64],
    "approved": True,
    "approval_required": True,
    "graph": True,
    "neo4j": "NEO4J_READY_WITH_DATA",
    "freshness": "CURRENT",
}


@pytest.mark.parametrize(
    "changes,state",
    [
        ({}, "EVIDENCE_READY"),
        ({"postgres": "POSTGRES_UNAVAILABLE"}, "DATABASE_UNAVAILABLE"),
        ({"postgres": "POSTGRES_STARTING"}, "DATABASE_STARTING"),
        ({"postgres": "POSTGRES_READY_EMPTY"}, "DATABASE_EMPTY"),
        ({"postgres": "POSTGRES_SCHEMA_MISMATCH"}, "DATABASE_SCHEMA_MISMATCH"),
        ({"selected_missing": True}, "APPROVED_REPORT_MISSING"),
        ({"selected": []}, "REPORT_SELECTION_REQUIRED"),
        ({"approved": False}, "REPORTS_AVAILABLE_NONE_APPROVED"),
        ({"graph": False}, "CAUSAL_GRAPH_MISSING"),
        ({"neo4j": "NEO4J_UNAVAILABLE"}, "NEO4J_UNAVAILABLE"),
        ({"freshness": "MISSING"}, "NEO4J_PROJECTION_MISSING"),
        ({"freshness": "STALE"}, "PROJECTION_STALE"),
        ({"freshness": "INCONSISTENT"}, "PROJECTION_INCONSISTENT"),
    ],
)
def test_operational_states(changes, state):
    result = classify(dict(BASE, **changes))
    assert result["state"] == state
    assert result["read_only"] is True
    assert result["message"]


def test_operator_actions_are_explicit_and_not_training():
    source = Path("scripts/analytical_runtime.py").read_text()
    assert 'choices=["doctor","migrate","data"]' in source.replace(" ", "")
    assert "train(" not in source and ".step(" not in source
    assert "SOURCE_VALIDATED_NOT_IMPORTED" in source


def test_runtime_modules_have_no_training_imports():
    for name in (
        "scripts/analytical_runtime.py",
        "src/rlredteam/application/runtime_readiness.py",
        "src/rlredteam/application/analytical_fixture.py",
    ):
        tree = ast.parse(Path(name).read_text())
        modules = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                modules.append(node.module or "")
            elif isinstance(node, ast.Import):
                modules.extend(a.name for a in node.names)
        assert not any(
            m.endswith((".train", ".environment", ".registered_onprem")) for m in modules
        )


def test_malformed_approval_configuration_blocks(monkeypatch):
    from rlredteam.api.services import AnalystService

    monkeypatch.setenv("SECURITY_RL_REQUIRE_REPORT_APPROVAL", "invalid")
    assert AnalystService().readiness()["state"] == "CONFIGURATION_INVALID"


def test_default_make_test_excludes_slow_training():
    text = Path("Makefile").read_text()
    body = text.split("test: ", 1)[1].split("test-fast:", 1)[0]
    assert '-m "not slow"' in body


def test_analytical_guard_refuses_inert_training_marker_before_execution(tmp_path):
    import subprocess
    import sys

    source = tmp_path / "test_inert_guard.py"
    source.write_text(
        "import pytest\n@pytest.mark.slow\ndef test_inert():\n"
        "    raise AssertionError('BODY_MUST_NOT_EXECUTE')\n"
    )
    result = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "-p",
            "rlredteam.application.analytical_test_guard",
            str(source),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 4
    assert "refuses slow/training/heldout" in result.stderr
    assert "BODY_MUST_NOT_EXECUTE" not in result.stdout


def test_analytical_runner_has_no_legacy_training_test_file():
    for path in ("scripts/test_runtime_podman.sh", "scripts/test_analytical_podman.sh"):
        text = Path(path).read_text()
        assert "test_postgres_logger.py" not in text
        assert "not slow" in text
    assert "tests/test_runtime" in Path("scripts/test_runtime_podman.sh").read_text()


def test_heldout_declarations_are_not_execution():
    from rlredteam.application.analytical_fixture import fixture_bundle
    from rlredteam.storage.analytical_identity import build_analytical_report

    source, _, _, _ = fixture_bundle()
    source[0]["heldout_definitions"] = list(range(16001, 16021))
    report, _, _ = build_analytical_report(source, experiment_id="declaration-only-fixture")
    assert report.facts


def test_compose_has_no_trainer_or_host_output_mounts():
    import yaml

    data = yaml.safe_load(Path("compose.analytical.yml").read_text())
    assert set(data["services"]) == {"postgres", "neo4j", "operator"}
    mounts = data["services"]["operator"]["volumes"]
    assert ".:/app:ro" in mounts
    assert "analytical_runtime:/runtime" in mounts
    assert data["networks"]["analytical"]["internal"] is True
    assert "name" in data["networks"]["analytical"]


def test_unwritable_directory_preflight(tmp_path, monkeypatch):
    import importlib.util

    spec = importlib.util.spec_from_file_location("preflight", "scripts/runtime_preflight.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    class Result:
        returncode = 0
        stdout = json.dumps({"status": "PASS", "held_out_executed": False})

    monkeypatch.setattr(module, "run", lambda args: Result())
    monkeypatch.setattr(module.shutil, "which", lambda name: "/fake/" + name)
    tmp_path.chmod(0o555)
    try:
        result = module.inspect(output=tmp_path)
        assert result["checks"]["runtime_output"] is False
    finally:
        tmp_path.chmod(0o755)


def test_preflight_network_absent_does_not_create_network(monkeypatch):
    import importlib.util

    spec = importlib.util.spec_from_file_location("preflight", "scripts/runtime_preflight.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    calls = []

    def run(args):
        from types import SimpleNamespace

        calls.append(args)
        return SimpleNamespace(
            returncode=1 if args[1:3] == ["network", "exists"] else 0,
            stdout=json.dumps({"status": "PASS", "held_out_executed": False}),
        )

    monkeypatch.setattr(module, "run", run)
    monkeypatch.setattr(module.shutil, "which", lambda name: "/fake/" + name)
    result = module.inspect()
    assert result["checks"]["network_exists"] is False
    assert not any("create" in command or "up" in command for command in calls)


def test_preflight_invalid_port_is_rejected_without_service_start(monkeypatch):
    import importlib.util

    spec = importlib.util.spec_from_file_location("preflight", "scripts/runtime_preflight.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("POSTGRES_PORT", "0")
    assert module.configuration_checks()["postgres_port_valid"] is False
    monkeypatch.setenv("POSTGRES_PORT", "15433")
    assert module.configuration_checks()["postgres_port_valid"] is True


@pytest.mark.parametrize(
    "state,expected", [("healthy", "READY"), ("starting", "BLOCKED"), ("unhealthy", "BLOCKED")]
)
def test_service_wait_uses_project_labels_without_side_effects(monkeypatch, state, expected):
    import importlib.util
    from types import SimpleNamespace

    spec = importlib.util.spec_from_file_location("preflight", "scripts/runtime_preflight.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    calls = []

    def run(args):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout=state if args[1] == "inspect" else "abc123")

    monkeypatch.setattr(module, "run", run)
    assert module.wait_services("test-project", timeout=0)["overall"] == expected
    assert all(command[1] in {"ps", "inspect"} for command in calls)
