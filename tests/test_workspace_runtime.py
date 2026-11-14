import json
import secrets
from dataclasses import replace
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from rlredteam.api.workspace_runtime import configuration_guard, create_configured_app, private_read
from rlredteam.knowledge.vulnerabilities.serialization import dumps as knowledge_dumps
from rlredteam.observation.serialization import dumps
from tests import test_assessment_jobs
from tests.test_inventory_correlation import knowledge, release

db = test_assessment_jobs.db
ready = test_assessment_jobs.ready
generated = test_assessment_jobs.generated


def private_file(root, value):
    path = root / (uuid4().hex + ".json")
    path.write_text(value)
    path.chmod(0o600)
    return str(path)


def test_private_config_rejects_permissive_files_and_symlinks(tmp_path):
    path = tmp_path / uuid4().hex
    path.write_text(json.dumps({}))
    path.chmod(0o644)
    with pytest.raises(ValueError, match="owner-only"):
        private_read(path)
    path.chmod(0o600)
    link = tmp_path / uuid4().hex
    link.symlink_to(path)
    with pytest.raises(ValueError, match="symlink"):
        private_read(link)


@pytest.mark.parametrize("configured", [False, True])
def test_default_workspace_disables_collection_and_requires_auth(tmp_path, monkeypatch, configured):
    monkeypatch.delenv("SECURITY_RL_WORKSPACE_CONFIG", raising=False)
    if configured:
        monkeypatch.setenv(
            "SECURITY_RL_WORKSPACE_CONFIG", private_file(tmp_path, json.dumps({"version": 1}))
        )
    token = secrets.token_hex(32)
    monkeypatch.setenv("SECURITY_RL_API_TOKEN", token)
    with TestClient(create_configured_app()) as client:
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/workspace/live/configuration").status_code == 401
        client.headers["Authorization"] = "Bearer " + token
        assert client.get("/api/workspace/live/configuration").json()["enabled"] is False
        assert client.get("/api/workspace/jobs").json()["state"] == "UNCONFIGURED"


def test_selected_missing_workspace_config_does_not_silently_fallback(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_RL_WORKSPACE_CONFIG", str(tmp_path / "missing.json"))
    with pytest.raises(FileNotFoundError):
        create_configured_app()


def test_private_file_change_invalidates_running_collector_context(tmp_path):
    selected = private_file(tmp_path, "{}")
    knowledge_path = private_file(tmp_path, "{}")
    scope_path, auth_path = private_file(tmp_path, "{}"), private_file(tmp_path, "{}")
    _, validate = configuration_guard(selected, {
        "vulnerability_snapshot": knowledge_path,
        "approvals": [{"scope_file": scope_path, "authorization_file": auth_path}],
    })
    validate()
    from pathlib import Path

    Path(scope_path).write_text('{"changed":true}')
    with pytest.raises(ValueError, match="restart and request a new plan"):
        validate()


@pytest.mark.parametrize("document", [
    {"version": True}, {"version": 1.0}, {"version": 1, "approvals": {}},
])
def test_malformed_workspace_field_types_are_rejected(tmp_path, monkeypatch, document):
    monkeypatch.setenv("SECURITY_RL_WORKSPACE_CONFIG", private_file(tmp_path, json.dumps(document)))
    with pytest.raises(ValueError, match="configuration"):
        create_configured_app()


@pytest.mark.parametrize("live", [False, True])
def test_configured_api_runs_pipeline_with_real_postgres(
    ready, generated, tmp_path, monkeypatch, live
):
    from rlredteam.storage import postgres_logger

    service, values, _, _ = generated
    scope, auth = service.approvals[values["scope_id"]]
    scope = replace(scope, live_enabled=live)
    config = dict(
        version=1,
        offline_processing_enabled=True,
        approvals=[
            dict(
                scope_file=private_file(tmp_path, dumps(scope)),
                authorization_file=private_file(tmp_path, dumps(auth)),
            )
        ],
        vulnerability_snapshot=private_file(
            tmp_path, knowledge_dumps(knowledge(uuid4().hex, uuid4().hex, release()))
        ),
        state_directory=str(tmp_path / uuid4().hex),
    )
    if live:
        from rlredteam.observation import controlled_collection

        config["collection_budget"] = dict(
            max_targets=1,
            max_runtime_seconds=scope.max_duration_seconds,
            max_retries=0,
            max_concurrency=1,
            max_ports=1,
            max_artifact_bytes=1024 * 1024,
            allowed_ports=values["ports"],
            execution_enabled=True,
        )
        monkeypatch.setattr(
            controlled_collection, "execute_bounded", lambda *args: values["xml"].encode()
        )
    monkeypatch.setenv("SECURITY_RL_WORKSPACE_CONFIG", private_file(tmp_path, json.dumps(config)))
    token = secrets.token_hex(32)
    monkeypatch.setenv("SECURITY_RL_API_TOKEN", token)
    monkeypatch.setattr(postgres_logger, "connection_string", lambda: ready.connection.info.dsn)
    with TestClient(create_configured_app()) as client:
        client.headers["Authorization"] = "Bearer " + token
        if live:
            requested = {
                key: values[key] for key in ("scope_id", "authorization_id", "target", "ports")
            }
            requested["profile"] = controlled_collection.PROFILE
            plan = client.post("/api/workspace/live/plan", json=requested)
            assert plan.status_code == 200
            response = client.post(
                "/api/workspace/live/collect",
                json={
                    **requested,
                    "operator_approved": True,
                    "plan_digest": plan.json()["plan_digest"],
                },
            )
        else:
            response = client.post("/api/workspace/jobs/offline", json=values)
        assert response.status_code == 200
        assert response.json()["events"][-1]["state"] == "COMPLETE"
        job_id = response.json()["events"][0]["job_id"]
        report = client.get(f"/api/workspace/jobs/{job_id}/views/report")
        assert report.status_code == 200
        assert report.json()["acquisition_mode"] == ("LIVE_LAB" if live else "OFFLINE_IMPORT")
        result = client.get("/api/workspace/correlations")
        assert result.status_code == 200 and len(result.json()["items"]) == 1
        assert client.get("/api/workspace/jobs").json()["items"][0]["state"] == "COMPLETE"
