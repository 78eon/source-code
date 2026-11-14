import sqlite3
from uuid import uuid4

import pytest

from rlredteam.application.assessment_jobs import STAGES, AssessmentJournal, OfflineAssessmentRunner
from rlredteam.knowledge.validation import ModelError
from tests import test_canonical_workspace, test_lab_input
from tests.test_inventory_correlation import knowledge, release

db = test_canonical_workspace.db
ready = test_canonical_workspace.ready
generated = test_lab_input.generated


@pytest.fixture
def runner(ready, generated, tmp_path):
    lab, values, raw_repo, _ = generated
    lab.evidence_repository = ready.twins.entities.evidence
    with sqlite3.connect(
        tmp_path / (uuid4().hex + ".sqlite"), check_same_thread=False
    ) as connection:
        journal = AssessmentJournal(connection)
        journal.initialize()
        service = OfflineAssessmentRunner(
            lab, ready, journal, knowledge(uuid4().hex, uuid4().hex, release())
        )
        yield service, values, raw_repo, ready


def test_offline_xml_to_persisted_correlation_and_job_provenance(runner):
    service, values, raw_repo, store = runner
    events = service.run(values)
    assert tuple(e["state"] for e in events) == STAGES
    data = events[-1]["data"]
    assert data["scope_id"] == values["scope_id"]
    assert data["authorization_id"] == values["authorization_id"]
    assert raw_repo.load_bundle(data["raw_bundle_id"]).session.session_id == data["session_id"]
    assert store.twins.entities.evidence.load(data["evidence_bundle_id"]).records
    correlation = store.load(data["correlation_id"])
    snapshot = store.twins.load(correlation.snapshot_id)
    assert not snapshot.assets and snapshot.unprojected
    assert data["ranking"] is None and data["planner_state"] == "BLOCKED"
    assert not data["network_execution"]
    with pytest.raises(ModelError, match="transition"):
        service.journal.append(events[0]["job_id"], "CREATED", {})


def test_invalid_scope_never_reaches_persistence(runner):
    service, values, raw_repo, store = runner
    events = service.run({**values, "scope_id": uuid4().hex})
    assert tuple(e["state"] for e in events) == ("CREATED", "FAILED")
    assert not raw_repo.list_sessions()
    assert not store.twins.entities.evidence.list()


def test_cancel_is_safe_between_stages(runner):
    service, values, raw_repo, _ = runner
    events = service.run(values, cancelled=lambda: True)
    assert events[-1]["state"] == "CANCELLED"
    assert not raw_repo.list_sessions()


def test_persistence_failure_stops_pipeline_but_preserves_raw(runner, monkeypatch):
    service, values, raw_repo, store = runner

    def denied(*args, **kwargs):
        raise RuntimeError("injected persistence failure")

    monkeypatch.setattr(service.lab.evidence_repository, "save", denied)
    events = service.run(values)
    assert events[-1]["state"] == "FAILED"
    assert events[-2]["state"] == "PERSISTING"
    assert raw_repo.list_sessions()
    assert not store.twins.entities.evidence.list()


def test_offline_job_api_cannot_bypass_auth_or_scope(runner, monkeypatch):
    import secrets

    from fastapi.testclient import TestClient

    from rlredteam.api.app import create_app

    service, values, _, _ = runner
    token = secrets.token_hex(32)
    monkeypatch.setenv("SECURITY_RL_API_TOKEN", token)
    with TestClient(create_app(lab_input_service=service.lab, assessment_runner=service)) as client:
        endpoint = "/api/workspace/jobs/offline"
        assert client.post(endpoint, json=values).status_code == 401
        client.headers["Authorization"] = "Bearer " + token
        assert client.post(endpoint, json={**values, "approved": True}).status_code == 422
        response = client.post(endpoint, json=values)
        assert response.status_code == 200
        assert response.json()["events"][-1]["state"] == "COMPLETE"
        assert not response.json()["network_execution"]
