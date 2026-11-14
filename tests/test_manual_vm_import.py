"""Generated manual imports through authenticated API and real disposable PostgreSQL."""

import secrets
import socket
import subprocess
from contextlib import contextmanager
from hashlib import sha256

import pytest
from fastapi.testclient import TestClient

from rlredteam.api.app import create_app
from rlredteam.application.canonical_workspace import SECTIONS, CanonicalWorkspace
from rlredteam.enterprise import live
from rlredteam.observation.serialization import dumps
from tests import test_assessment_jobs

db = test_assessment_jobs.db
ready = test_assessment_jobs.ready
generated = test_assessment_jobs.generated
runner = test_assessment_jobs.runner


@pytest.fixture
def client(runner, monkeypatch):
    service, _, _, store = runner

    @contextmanager
    def factory():
        yield store

    def forbidden(*args, **kwargs):
        raise AssertionError("manual import must not execute scanning or legacy graph logic")

    monkeypatch.setattr(live.NmapLabRunner, "run", forbidden)
    monkeypatch.setattr(live.LiveKnowledgeGraph, "__init__", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    token = secrets.token_hex(32)
    monkeypatch.setenv("SECURITY_RL_API_TOKEN", token)
    with TestClient(
        create_app(
            lab_input_service=service.lab,
            assessment_runner=service,
            workspace_service=CanonicalWorkspace(factory),
        )
    ) as api:
        api.headers["Authorization"] = "Bearer " + token
        yield api


def test_import_all_views_and_full_provenance(client, runner):
    service, values, raw_repo, store = runner
    response = client.post("/api/workspace/jobs/offline", json=values)
    assert response.status_code == 200
    events = response.json()["events"]
    assert events[-1]["state"] == "COMPLETE"
    job_id = events[0]["job_id"]
    data = events[-1]["data"]
    raw = raw_repo.load_bundle(data["raw_bundle_id"])
    original = dumps(raw)
    checksum = sha256(values["xml"].encode()).hexdigest()
    assert raw.metadata["source_artifact"]["content"] == values["xml"]
    assert raw.metadata["source_artifact"]["sha256"] == checksum
    assert events[1]["data"]["source_artifact_sha256"] == checksum
    evidence = store.twins.entities.evidence.load(data["evidence_bundle_id"])
    raw_ids = {r.observation_id for r in raw.observations}
    for record in evidence.records:
        assert record.provenance.attributes["raw_observation_id"] in raw_ids
        assert record.provenance.attributes["session_id"] == data["session_id"]
        assert record.provenance.attributes["input_digest"]
    for section in SECTIONS:
        result = client.get(f"/api/workspace/jobs/{job_id}/views/{section}")
        assert result.status_code == 200, result.text
        value = result.json()
        assert value["snapshot_id"] == data["snapshot_id"]
        assert value["import_provenance"]["source_artifact"]["sha256"] == checksum
        assert value["observed_inventory"]["ObservedAsset"]
        assert value["observed_inventory"]["ObservedService"]
        assert value["observed_inventory"]["ObservedSoftware"]
        assert not value["execution_enabled"]
    report = client.get(f"/api/workspace/jobs/{job_id}/views/report").json()
    assert report["data"]["paths"]["state"] == "UNRESOLVED"
    assert report["data"]["advisory"]["state"] == "BLOCKED"
    assert report["data"]["attack"]["state"] == "UNKNOWN"
    assert report["import_provenance"]["authorization_digest"]
    assert report["import_provenance"]["audit"]["events"]
    assert report["unprojected"] and not report["data"]["assets"]
    assert raw_repo.load_audit(raw.session.session_id).events
    assert dumps(raw_repo.load_bundle(raw.bundle_id)) == original
    assert not response.json()["network_execution"]


def test_duplicate_xml_is_a_separate_append_only_session(client, runner):
    _, values, raw_repo, store = runner
    first = client.post("/api/workspace/jobs/offline", json=values).json()["events"][-1]
    before = dumps(raw_repo.load_bundle(first["data"]["raw_bundle_id"]))
    evidence = store.twins.entities.evidence.load(first["data"]["evidence_bundle_id"])
    second = client.post("/api/workspace/jobs/offline", json=values).json()["events"][-1]
    assert first["state"] == second["state"] == "COMPLETE"
    for field in ("session_id", "raw_bundle_id", "evidence_bundle_id", "snapshot_id"):
        assert first["data"][field] != second["data"][field]
    assert first["job_id"] != second["job_id"]
    assert dumps(raw_repo.load_bundle(first["data"]["raw_bundle_id"])) == before
    assert store.twins.entities.evidence.load(evidence.bundle_id) == evidence
    assert len(raw_repo.list_sessions()) == 2


def test_malformed_xml_and_metadata_override_cannot_publish(client, runner):
    _, values, raw_repo, store = runner
    for field in ("product", "interface", "allowed_networks", "operator_notes"):
        response = client.post(
            "/api/workspace/jobs/offline",
            json={
                **values,
                field: secrets.token_hex(),
            },
        )
        assert response.status_code == 422
    result = client.post("/api/workspace/jobs/offline", json={**values, "xml": "<"}).json()
    assert result["events"][-1]["state"] == "FAILED"
    job_id = result["events"][0]["job_id"]
    assert client.get(f"/api/workspace/jobs/{job_id}/views/report").json()["state"] == "FAILED"
    assert not raw_repo.list_sessions()
    assert not store.twins.entities.evidence.list()


def test_import_views_require_auth_and_existing_job(client):
    path = "/api/workspace/jobs/" + secrets.token_hex() + "/views/report"
    assert client.get(path).status_code == 404
    client.headers.pop("Authorization")
    assert client.get(path).status_code == 401
