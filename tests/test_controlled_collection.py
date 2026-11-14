"""Generated targets and fake acquisition; never scans a real VM."""

import asyncio
import base64
import json
import secrets
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from threading import Event

import pytest
from fastapi.testclient import TestClient

from rlredteam.api.app import create_app
from rlredteam.application.assessment_jobs import LIVE_STAGES
from rlredteam.enterprise import live
from rlredteam.observation.controlled_collection import (
    PROFILE,
    CollectionBudget,
    ControlledNmapCollector,
    execute_bounded,
)
from rlredteam.observation.serialization import dumps
from tests import test_assessment_jobs

db = test_assessment_jobs.db
ready = test_assessment_jobs.ready
generated = test_assessment_jobs.generated
runner = test_assessment_jobs.runner


@pytest.fixture
def controlled(runner, monkeypatch):
    service, values, raw_repo, store = runner
    scope, auth = service.lab.approvals[values["scope_id"]]
    scope = replace(scope, live_enabled=True)
    approvals = {scope.scope_id: (scope, auth)}
    service.lab.approvals = approvals
    calls = []
    artifact = b"<!DOCTYPE nmaprun>" + values["xml"].encode()

    def acquire(argv, budget, cancelled, deadline):
        calls.append(tuple(argv))
        return artifact

    budget = CollectionBudget(
        max_targets=1,
        max_runtime_seconds=scope.max_duration_seconds,
        max_retries=0,
        max_concurrency=1,
        max_ports=1,
        max_artifact_bytes=1024 * 1024,
        allowed_ports=tuple(values["ports"]),
        execution_enabled=True,
    )
    collector = ControlledNmapCollector(approvals, budget, execute=acquire)
    service.collector = collector
    request = {key: values[key] for key in ("scope_id", "authorization_id", "target", "ports")}
    request["profile"] = PROFILE

    def forbidden(*args, **kwargs):
        raise AssertionError("legacy graph is not an acquisition dependency")

    monkeypatch.setattr(live.LiveKnowledgeGraph, "__init__", forbidden)
    return service, request, collector, calls, artifact, raw_repo, store


@pytest.mark.parametrize(
    "case",
    [
        "disabled",
        "missing_auth",
        "wrong_auth",
        "scope_disabled",
        "wrong_scope",
        "excluded",
        "excess_ports",
        "unapproved_port",
        "profile",
        "names",
        "multiple_targets",
        "duration",
        "retry_budget",
        "host_budget",
        "capability",
    ],
)
def test_rejections_precede_acquisition(controlled, case, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("rejected requests must never reach subprocesses or sockets")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    _, request, collector, calls, _, _, _ = controlled
    scope, auth = collector.approvals[request["scope_id"]]
    if case == "disabled":
        collector.budget = replace(collector.budget, execution_enabled=False)
    elif case == "missing_auth":
        collector.approvals = {}
    elif case == "wrong_auth":
        request = {**request, "authorization_id": secrets.token_hex()}
    elif case == "wrong_scope":
        request = {**request, "scope_id": secrets.token_hex()}
    elif case == "scope_disabled":
        scope = replace(scope, live_enabled=False)
    elif case == "excluded":
        scope = replace(scope, excluded_assets=(request["target"],))
    elif case == "capability":
        scope = replace(scope, capability_allowlist=())
    elif case == "excess_ports":
        request = {**request, "ports": [*request["ports"], request["ports"][0] % 65535 + 1]}
    elif case == "unapproved_port":
        request = {**request, "ports": [request["ports"][0] % 65535 + 1]}
    elif case == "profile":
        request = {**request, "profile": secrets.token_hex()}
    elif case == "names":
        request = {**request, "target": secrets.token_hex()}
    elif case == "multiple_targets":
        request = {**request, "target": [request["target"]] * 2}
    elif case == "duration":
        scope = replace(scope, max_duration_seconds=collector.budget.max_runtime_seconds - 1)
    elif case == "host_budget":
        with pytest.raises(ValueError):
            replace(collector.budget, max_targets=2)
        assert not calls
        return
    elif case == "retry_budget":
        scope = replace(scope, max_requests_per_asset=1)
        collector.budget = replace(collector.budget, max_retries=1)
    if case not in ("missing_auth",):
        collector.approvals[scope.scope_id] = (scope, auth)
    with pytest.raises((ValueError, TypeError)):
        collector.collect(request, plan_digest=secrets.token_hex(32), operator_approved=True)
    assert calls == []


def test_exact_plan_approval_deadline_and_cancel(controlled):
    _, values, collector, calls, _, _, _ = controlled
    plan = collector.plan(**values)
    assert str(values["ports"][0]) in plan["argv"]
    assert values["target"] == plan["argv"][-1]
    for changes in (
        {"operator_approved": False},
        {"plan_digest": secrets.token_hex(32)},
        {"cancelled": lambda: True},
        {"deadline": time.monotonic() - 1},
    ):
        inputs = dict(plan_digest=plan["plan_digest"], operator_approved=True)
        with pytest.raises((ValueError, InterruptedError, TimeoutError)):
            collector.collect(values, **{**inputs, **changes})
    assert not calls


def test_only_inert_header_doctype_is_accepted(controlled):
    xml = controlled[4].removeprefix(b"<!DOCTYPE nmaprun>")
    assert live.parse_nmap_xml(b'<?xml version="1.0"?>\n<!DOCTYPE nmaprun>\n' + xml).hosts
    for declaration in (
        b'<!DOCTYPE nmaprun SYSTEM "file:///untrusted">',
        b'<!DOCTYPE nmaprun [<!ENTITY injected "text">]>',
        b"<!DOCTYPE nmaprun><!DOCTYPE nmaprun>",
    ):
        with pytest.raises(ValueError):
            live.parse_nmap_xml(declaration + xml)


def test_expired_authority_and_concurrent_run_fail_closed(controlled):
    _, values, collector, calls, _, _, _ = controlled
    plan = collector.plan(**values)
    collector.lock.acquire()
    try:
        with pytest.raises(ValueError, match="already active"):
            collector.collect(values, plan_digest=plan["plan_digest"], operator_approved=True)
    finally:
        collector.lock.release()
    scope, auth = collector.approvals[values["scope_id"]]
    now = datetime.now(UTC)
    auth = replace(
        auth,
        valid_from=(now - timedelta(days=2)).isoformat(),
        valid_until=(now - timedelta(days=1)).isoformat(),
        digest="",
    )
    collector.approvals[scope.scope_id] = (scope, auth)
    with pytest.raises(ValueError):
        collector.collect(values, plan_digest=plan["plan_digest"], operator_approved=True)
    assert not calls


def test_live_pipeline_preserves_exact_bytes_and_separate_histories(controlled):
    service, values, collector, calls, artifact, raw_repo, store = controlled
    plan = collector.plan(**values)
    approved = {**values, "operator_approved": True, "plan_digest": plan["plan_digest"]}
    events = service.run_live(approved)
    assert tuple(e["state"] for e in events) == LIVE_STAGES
    captured = next(e["data"] for e in events if e["state"] == "COLLECTED")
    assert base64.b64decode(captured["artifact_base64"]) == artifact
    assert captured["source_artifact_sha256"] == sha256(artifact).hexdigest()
    data = events[-1]["data"]
    raw = raw_repo.load_bundle(data["raw_bundle_id"])
    before = dumps(raw)
    assert raw.session.mode.value == "LIVE_LAB"
    assert raw.metadata["source_artifact"]["content"].encode() == artifact
    assert raw.metadata["acquisition"]["job_id"] == events[0]["job_id"]
    assert raw_repo.load_audit(raw.session.session_id).events
    assert store.twins.entities.evidence.load(data["evidence_bundle_id"]).records
    # Each acquisition attempt needs a newly reviewed backend plan.
    second_plan = collector.plan(**values)
    assert second_plan["plan_digest"] != plan["plan_digest"]
    second = service.run_live({**approved, "plan_digest": second_plan["plan_digest"]})
    assert second[-1]["state"] == "COMPLETE"
    assert second[-1]["data"]["session_id"] != data["session_id"]
    assert dumps(raw_repo.load_bundle(raw.bundle_id)) == before
    assert len(calls) == 2


@pytest.mark.parametrize("failure", ["collector", "malformed", "overflow", "cancel"])
def test_failures_never_publish_complete(controlled, failure):
    service, values, collector, _, _, raw_repo, store = controlled
    plan = collector.plan(**values)

    def execute(*args):
        if failure == "collector":
            raise RuntimeError("fake collector failure")
        if failure == "cancel":
            raise InterruptedError("fake cancellation")
        if failure == "overflow":
            return b"x" * (collector.budget.max_artifact_bytes + 1)
        return b"<"

    collector.execute = execute
    events = service.run_live(
        {**values, "operator_approved": True, "plan_digest": plan["plan_digest"]}
    )
    assert events[-1]["state"] == ("CANCELLED" if failure == "cancel" else "FAILED")
    assert not raw_repo.list_sessions()
    assert not store.twins.entities.evidence.list()
    if failure == "malformed":
        assert base64.b64decode(events[-2]["data"]["artifact_base64"]) == b"<"


def test_api_rejects_frontend_permissions_and_runs_only_approved_plan(controlled, monkeypatch):
    service, values, _, calls, _, _, _ = controlled
    token = secrets.token_hex(32)
    monkeypatch.setenv("SECURITY_RL_API_TOKEN", token)
    with TestClient(create_app(assessment_runner=service)) as client:
        root = "/api/workspace/live"
        assert client.post(root + "/plan", json=values).status_code == 401
        client.headers["Authorization"] = "Bearer " + token
        assert client.get(root + "/configuration").json()["enabled"]
        plan = client.post(root + "/plan", json=values).json()
        assert "argv" not in plan
        assert not calls
        approved = {**values, "operator_approved": True, "plan_digest": plan["plan_digest"]}
        for forbidden in ("command", "budget", "execution_enabled", "xml"):
            assert (
                client.post(
                    root + "/collect", json={**approved, forbidden: secrets.token_hex()}
                ).status_code
                == 422
            )
        assert (
            client.post(
                root + "/collect", json={**approved, "operator_approved": False}
            ).status_code
            == 422
        )
        assert not calls
        result = client.post(root + "/collect", json=approved)
        assert result.status_code == 200
        assert result.json()["events"][-1]["state"] == "COMPLETE"
        assert len(calls) == 1


def test_concurrent_api_collections_execute_only_one_approved_plan(controlled, monkeypatch):
    service, values, collector, calls, artifact, _, _ = controlled
    started, release = Event(), Event()

    def acquire(*args):
        calls.append(args[0])
        started.set()
        assert release.wait(5)
        return artifact

    collector.execute = acquire
    token = secrets.token_hex(32)
    monkeypatch.setenv("SECURITY_RL_API_TOKEN", token)
    plan = collector.plan(**values)
    approved = {**values, "operator_approved": True, "plan_digest": plan["plan_digest"]}
    with TestClient(create_app(assessment_runner=service)) as client:
        client.headers["Authorization"] = "Bearer " + token
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(client.post, "/api/workspace/live/collect", json=approved)
            try:
                assert started.wait(5)
                second = client.post("/api/workspace/live/collect", json=approved)
                assert second.status_code == 422  # the first request consumed this plan
            finally:
                release.set()
            assert first.result(timeout=10).json()["events"][-1]["state"] == "COMPLETE"
    assert len(calls) == 1


def test_scope_change_and_new_runtime_invalidate_old_approval(controlled):
    _, values, collector, calls, _, _, _ = controlled
    old = collector.plan(**values)
    scope, auth = collector.approvals[values["scope_id"]]
    collector.approvals[scope.scope_id] = (replace(
        scope, max_requests_per_asset=scope.max_requests_per_asset + 1
    ), auth)
    with pytest.raises(ValueError, match="approval"):
        collector.collect(values, plan_digest=old["plan_digest"], operator_approved=True)
    current = collector.plan(**values)
    other = ControlledNmapCollector(
        collector.approvals, collector.budget, execute=collector.execute
    )
    with pytest.raises(ValueError, match="approval"):
        other.collect(values, plan_digest=current["plan_digest"], operator_approved=True)
    assert not calls


def test_failed_acquisition_consumes_plan_and_retry_needs_fresh_approval(controlled):
    _, values, collector, calls, _, _, _ = controlled
    old = collector.plan(**values)

    def interrupted(*args):
        calls.append(args)
        raise InterruptedError("mock interruption")

    collector.execute = interrupted
    with pytest.raises(InterruptedError):
        collector.collect(values, plan_digest=old["plan_digest"], operator_approved=True)
    with pytest.raises(ValueError, match="approval"):
        collector.collect(values, plan_digest=old["plan_digest"], operator_approved=True)
    assert len(calls) == 1
    assert collector.plan(**values)["plan_digest"] != old["plan_digest"]


def test_disconnected_api_collection_cancels_mock_worker(controlled, monkeypatch):
    service, values, collector, calls, _, raw_repo, store = controlled
    started = Event()

    def acquire(argv, budget, cancelled, deadline):
        calls.append(argv)
        started.set()
        while time.monotonic() < deadline and not cancelled():
            time.sleep(0.005)
        assert cancelled(), "mock worker must receive disconnect cancellation"
        raise InterruptedError("mock collection cancelled")

    collector.execute = acquire
    token = secrets.token_hex(32)
    monkeypatch.setenv("SECURITY_RL_API_TOKEN", token)
    plan = collector.plan(**values)
    body = json.dumps({**values, "operator_approved": True, "plan_digest": plan["plan_digest"]})
    app = create_app(assessment_runner=service)

    async def scenario():
        sent_body = False

        async def receive():
            nonlocal sent_body
            if not sent_body:
                sent_body = True
                return {"type": "http.request", "body": body.encode(), "more_body": False}
            if started.is_set():
                return {"type": "http.disconnect"}
            await asyncio.sleep(0.01)
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            pass

        await asyncio.wait_for(app({
            "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
            "method": "POST", "scheme": "http", "path": "/api/workspace/live/collect",
            "query_string": b"", "headers": [
                (b"host", b"127.0.0.1"), (b"content-type", b"application/json"),
                (b"authorization", ("Bearer " + token).encode()),
            ],
        }, receive, send), timeout=5)

    asyncio.run(scenario())
    jobs = service.journal.jobs()
    assert len(jobs) == len(calls) == 1
    assert jobs[0]["state"] == "CANCELLED"
    assert not raw_repo.list_sessions()
    assert not store.twins.entities.evidence.list()


@pytest.mark.parametrize("failure", ["success", "overflow", "timeout", "cancel", "exit"])
def test_subprocess_stream_bounds_without_network(controlled, failure):
    budget = replace(controlled[2].budget, max_artifact_bytes=64)
    command = [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x')"]
    if failure == "overflow":
        command[-1] = "import sys; sys.stdout.buffer.write(b'x'*1024)"
    if failure in ("timeout", "cancel"):
        command[-1] = "import time; time.sleep(10)"
    if failure == "exit":
        command[-1] = "raise SystemExit(1)"
    began = time.monotonic()

    def cancelled():
        return failure == "cancel" and time.monotonic() - began > 0.05

    if failure == "success":
        assert execute_bounded(command, budget, cancelled, began + 2) == b"x"
    else:
        with pytest.raises((ValueError, TimeoutError, InterruptedError, RuntimeError)):
            execute_bounded(
                command, budget, cancelled, began + (0.05 if failure == "timeout" else 2)
            )
