"""Composed runtime over disposable stores; all collection is mocked or forbidden."""

import json
import os
import secrets
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from rlredteam.api.workspace_runtime import create_configured_app
from rlredteam.application.assessment_jobs import AssessmentJournal
from rlredteam.application.canonical_workspace import SECTIONS
from rlredteam.knowledge.vulnerabilities.serialization import dumps as knowledge_dumps
from rlredteam.observation.serialization import dumps
from rlredteam.observation.serialization import loads as observation_loads
from tests import test_assessment_jobs
from tests.test_inventory_correlation import knowledge, release
from tests.test_workspace_runtime import private_file

db = test_assessment_jobs.db
ready = test_assessment_jobs.ready
generated = test_assessment_jobs.generated


@pytest.fixture
def configured_runtime(ready, generated, tmp_path, monkeypatch):
    from rlredteam.observation import controlled_collection
    from rlredteam.storage import postgres_logger

    service, values, _, _ = generated
    scope, authorization = service.approvals[values["scope_id"]]
    config = {
        "version": 1,
        "offline_processing_enabled": True,
        "approvals": [{
            "scope_file": private_file(tmp_path, dumps(scope)),
            "authorization_file": private_file(tmp_path, dumps(authorization)),
        }],
        "vulnerability_snapshot": private_file(
            tmp_path, knowledge_dumps(knowledge(uuid4().hex, uuid4().hex, release()))
        ),
        "state_directory": str(tmp_path / "state"),
    }
    monkeypatch.setenv("SECURITY_RL_WORKSPACE_CONFIG", private_file(tmp_path, json.dumps(config)))
    token = secrets.token_hex(32)
    monkeypatch.setenv("SECURITY_RL_API_TOKEN", token)
    monkeypatch.setattr(postgres_logger, "connection_string", lambda: ready.connection.info.dsn)

    def forbidden(*args, **kwargs):
        raise AssertionError("offline runtime must not invoke collection")

    monkeypatch.setattr(controlled_collection, "execute_bounded", forbidden)
    return values, {"Authorization": "Bearer " + token}, config, ready


def test_configured_manual_import_all_views_survive_restart(configured_runtime):
    values, headers, _, _ = configured_runtime
    with TestClient(create_configured_app(), headers=headers) as client:
        result = client.post("/api/workspace/jobs/offline", json=values)
        assert result.status_code == 200
        events = result.json()["events"]
        assert events[-1]["state"] == "COMPLETE"
        job_id = events[0]["job_id"]
        reports = {}
        for section in SECTIONS:
            response = client.get(f"/api/workspace/jobs/{job_id}/views/{section}")
            assert response.status_code == 200
            reports[section] = response.json()
            assert reports[section]["execution_enabled"] is False
        assert reports["report"]["data"]["paths"]["state"] == "UNRESOLVED"
        assert reports["report"]["data"]["advisory"]["state"] == "BLOCKED"
    with TestClient(create_configured_app(), headers=headers) as client:
        assert client.get(f"/api/workspace/jobs/{job_id}").json()["events"] == events
        for section, before in reports.items():
            assert client.get(f"/api/workspace/jobs/{job_id}/views/{section}").json() == before
        assert client.get("/api/workspace/live/configuration").json()["enabled"] is False


def test_configured_concurrent_imports_and_reads_keep_separate_histories(configured_runtime):
    values, headers, _, _ = configured_runtime
    with TestClient(create_configured_app(), headers=headers) as client:
        def import_and_read(_):
            response = client.post("/api/workspace/jobs/offline", json=values)
            assert response.status_code == 200
            events = response.json()["events"]
            assert events[-1]["state"] == "COMPLETE"
            job = events[0]["job_id"]
            assert client.get(f"/api/workspace/jobs/{job}/views/report").status_code == 200
            assert client.get("/api/workspace/jobs").status_code == 200
            return events[-1]

        with ThreadPoolExecutor(max_workers=4) as pool:
            final = list(pool.map(import_and_read, range(8)))
        assert len({event["job_id"] for event in final}) == 8
        for field in ("session_id", "snapshot_id", "evidence_bundle_id"):
            assert len({event["data"][field] for event in final}) == 8


def test_configured_database_unavailable_then_recovery(configured_runtime, monkeypatch):
    from rlredteam.storage import postgres_logger

    values, headers, _, ready = configured_runtime
    with TestClient(create_configured_app(), headers=headers) as client:
        monkeypatch.setattr(
            postgres_logger, "connection_string",
            lambda: "host=127.0.0.1 port=1 connect_timeout=1 dbname=unavailable",
        )
        assert client.post("/api/workspace/jobs/offline", json=values).status_code == 503
        assert client.get("/api/workspace/jobs").json()["items"] == []
        monkeypatch.setattr(postgres_logger, "connection_string", lambda: ready.connection.info.dsn)
        result = client.post("/api/workspace/jobs/offline", json=values)
        assert result.status_code == 200
        assert result.json()["events"][-1]["state"] == "COMPLETE"


def test_restart_keeps_interrupted_history_without_resuming_collection(configured_runtime):
    _, headers, config, _ = configured_runtime
    with TestClient(create_configured_app(), headers=headers):
        pass
    job = "assessment:" + uuid4().hex
    with sqlite3.connect(Path(config["state_directory"]) / "assessment-jobs.sqlite") as connection:
        journal = AssessmentJournal(connection)
        journal.append(job, "CREATED", {"mode": "LIVE_LAB", "network_execution": False})
        journal.append(job, "AUTHORIZED", {"synthetic_interrupted_job": True})
        before = journal.events(job)
    with TestClient(create_configured_app(), headers=headers) as client:
        recovered = client.get(f"/api/workspace/jobs/{job}").json()["events"]
        assert recovered[:-1] == before
        assert recovered[-1]["state"] == "FAILED"
        assert recovered[-1]["data"]["reason"] == "INTERRUPTED_RUNTIME"
        assert client.get("/api/workspace/live/configuration").json()["enabled"] is False
    # Retry remains a manual operation; restart never repeats collection.


def test_changed_private_scope_blocks_approved_mock_collection(configured_runtime, monkeypatch):
    from rlredteam.observation import controlled_collection

    values, headers, config, _ = configured_runtime
    scope_path = Path(config["approvals"][0]["scope_file"])
    scope = replace(observation_loads(scope_path.read_text()), live_enabled=True)
    scope_path.write_text(dumps(scope))
    config["collection_budget"] = dict(
        max_targets=1, max_runtime_seconds=scope.max_duration_seconds, max_retries=0,
        max_concurrency=1, max_ports=1, max_artifact_bytes=1048576,
        allowed_ports=values["ports"], execution_enabled=True,
    )
    Path(os.environ["SECURITY_RL_WORKSPACE_CONFIG"]).write_text(json.dumps(config))
    calls = []
    monkeypatch.setattr(controlled_collection, "execute_bounded",
                        lambda *a: calls.append(a) or values["xml"].encode())
    selected = {key: values[key] for key in ("scope_id", "authorization_id", "target", "ports")}
    selected["profile"] = controlled_collection.PROFILE
    with TestClient(create_configured_app(), headers=headers) as client:
        plan = client.post("/api/workspace/live/plan", json=selected)
        assert plan.status_code == 200
        scope_path.write_text(dumps(replace(
            scope, max_requests_per_asset=scope.max_requests_per_asset + 1
        )))
        response = client.post("/api/workspace/live/collect", json={
            **selected, "operator_approved": True, "plan_digest": plan.json()["plan_digest"],
        })
        assert response.status_code == 422
        assert client.get("/api/workspace/live/configuration").status_code == 503
    assert calls == []
