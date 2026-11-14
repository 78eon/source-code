"""No-scan preflight with generated private configuration and mocked OS probes."""

import importlib.util
import io
import json
import secrets
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from rlredteam.api.live_lab_readiness import (
    api_reasons,
    configuration_check,
    route_reasons,
    topology_reasons,
)
from rlredteam.knowledge.vulnerabilities.serialization import dumps as knowledge_dumps
from rlredteam.observation.controlled_collection import PROFILE
from rlredteam.observation.serialization import dumps
from tests import test_lab_input
from tests.test_inventory_correlation import knowledge, release
from tests.test_workspace_runtime import private_file

generated = test_lab_input.generated

SPEC = importlib.util.spec_from_file_location("live_preflight", "scripts/live_lab_preflight.py")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def test_configuration_plan_is_read_only_and_requires_no_operator_approval(
    generated, tmp_path, monkeypatch
):
    service, values, _, _ = generated
    scope, auth = service.approvals[values["scope_id"]]
    scope = replace(scope, live_enabled=True)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    document = dict(
        version=1,
        offline_processing_enabled=True,
        approvals=[
            dict(
                scope_file=private_file(tmp_path, dumps(scope)),
                authorization_file=private_file(tmp_path, dumps(auth)),
            )
        ],
        state_directory=str(state),
        vulnerability_snapshot=private_file(
            tmp_path,
            knowledge_dumps(knowledge(secrets.token_hex(), secrets.token_hex(), release())),
        ),
        collection_budget=dict(
            max_targets=1,
            max_runtime_seconds=scope.max_duration_seconds,
            max_retries=0,
            max_concurrency=1,
            max_ports=1,
            max_artifact_bytes=1048576,
            allowed_ports=values["ports"],
            execution_enabled=True,
        ),
    )
    path = private_file(tmp_path, json.dumps(document))
    request = {k: values[k] for k in ("scope_id", "authorization_id", "target", "ports")}
    request.update(profile=PROFILE, operator_approved=False)

    def forbidden(*args, **kwargs):
        raise AssertionError("preflight must never execute acquisition")

    from rlredteam.observation.controlled_collection import ControlledNmapCollector

    monkeypatch.setattr(ControlledNmapCollector, "collect", forbidden)
    before = sorted(state.iterdir())
    result = configuration_check(path, request)
    assert result["plan"]["approval_required"] is True
    assert sorted(state.iterdir()) == before
    with pytest.raises(ValueError, match="approval not yet granted"):
        configuration_check(path, {**request, "operator_approved": True})
    with pytest.raises(ValueError):
        configuration_check(path, {**request, "ports": [values["ports"][0] % 65535 + 1]})


def test_host_preflight_never_uses_host_network_or_nmap_executable(tmp_path, monkeypatch):
    config = tmp_path / "config"
    config.mkdir(mode=0o700)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    paths = [Path(private_file(config, "{}")) for _ in range(3)]
    monkeypatch.setattr(module, "workspace_paths", lambda *a, **k: (config, state, {}))
    calls = []

    def execute(argv):
        calls.append(argv)
        if argv[1] == "inspect":
            return SimpleNamespace(returncode=0, stdout="true\n")
        if "rlredteam.api.live_lab_readiness" in argv:
            return SimpleNamespace(
                returncode=0, stdout=json.dumps({"status": "READY", "reasons": []})
            )
        return SimpleNamespace(returncode=0, stdout="")

    result = module.inspect(
        {
            "SECURITY_RL_API_TOKEN": secrets.token_hex(32),
            "SECURITY_RL_WORKSPACE_CONFIG": str(paths[0]),
            "SECURITY_RL_LAB_NETWORK_CONTAINER": "generated-test-anchor",
        },
        str(paths[1]),
        str(paths[2]),
        execute=execute,
    )
    assert result == {"status": "READY", "reasons": []}
    for argv in calls:
        assert "nmap" not in argv
        assert "host" not in argv and "--privileged" not in argv
        if "--network" in argv:
            assert argv[argv.index("--network") + 1] in ("none", "container:generated-test-anchor")


def test_unavailable_runtime_and_namespace_block_without_raw_secret_output(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "workspace_paths", lambda *a, **k: (tmp_path, tmp_path, {}))
    path = private_file(tmp_path, "{}")
    result = module.inspect(
        {},
        path,
        path,
        execute=lambda argv: SimpleNamespace(
            returncode=1, stdout="private-diagnostic-must-not-leak"
        ),
    )
    assert result["status"] == "BLOCKED"
    assert "private-diagnostic" not in json.dumps(result)
    assert any("namespace" in reason for reason in result["reasons"])


def test_routing_evidence_does_not_turn_an_unverified_route_into_ready():
    # Documentation-range values are inert fixture input; no sockets or target traffic.
    target = "10.42.2.3"
    topology = dict(
        version=1,
        source="operator-supplied",
        live_introspection_available=False,
        kali=dict(address="10.42.1.2/24", route_network="10.42.2.0/24", route_via="10.42.1.3"),
        router=dict(
            attacker_address="10.42.1.3/24", internal_address="10.42.2.1/24", ipv4_forwarding=True
        ),
        web=dict(address=target + "/24", default_via="10.42.2.1"),
    )
    assert any("egress" in reason for reason in topology_reasons(topology, target))
    assert any("introspection" in reason for reason in topology_reasons(topology, target))
    assert route_reasons([], target, topology)
    assert route_reasons([dict(network="0.0.0.0/0", gateway="10.42.1.1")], target, topology)
    assert (
        route_reasons([dict(network="10.42.2.0/24", gateway="10.42.1.3")], target, topology) == []
    )


def test_preflight_timeout_does_not_wait_for_orphaned_stdout_helpers():
    code = ("import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',"
            "'import time; time.sleep(10)']); time.sleep(10)")
    began = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        module.run([sys.executable, "-c", code], timeout=0.05)
    assert time.monotonic() - began < 3


def test_preflight_missing_inputs_reports_only_blocked_json():
    result = subprocess.run([sys.executable, "-B", "scripts/live_lab_preflight.py"],
                            capture_output=True, text=True)
    assert result.returncode == 1 and result.stderr == ""
    assert json.loads(result.stdout)["status"] == "BLOCKED"


def test_preflight_api_identity_checks_use_only_loopback_gets(monkeypatch):
    from urllib import request as http

    token = secrets.token_hex(32)
    monkeypatch.setenv("SECURITY_RL_API_TOKEN", token)
    plan = dict(scope_id="generated-scope", scope_digest="a" * 64,
                authorization_digest="b" * 64, budget={"allowed_ports": [1]})
    expected = dict(plan=plan, configuration_digest="c" * 64, knowledge_digest="d" * 64)
    live = dict(enabled=True, scopes=[{k: plan[k] for k in (
        "scope_id", "scope_digest", "authorization_digest"
    )}], budget=plan["budget"], configuration_digest=expected["configuration_digest"],
                knowledge_digest=expected["knowledge_digest"])
    calls = []

    class Opener:
        def open(self, request, timeout):
            assert request.full_url.startswith("http://127.0.0.1:8765/api/")
            calls.append(request.get_method())
            document = live if request.full_url.endswith("configuration") else {}
            return io.StringIO(json.dumps(document))

    monkeypatch.setattr(http, "build_opener", lambda *a: Opener())
    assert api_reasons(expected) == []
    live["knowledge_digest"] = "e" * 64
    assert api_reasons(expected)
    assert calls == ["GET"] * 4
